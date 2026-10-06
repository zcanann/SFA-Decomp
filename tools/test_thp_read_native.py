#!/usr/bin/env python3
"""Run the production THP reader TU with native buffers and independent OS objects."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef int64_t s64;
typedef float f32;
typedef int BOOL;
typedef int OSPriority;
typedef void* OSMessage;
/* SDK services are adapters; production game records retain native pointers. */
typedef struct { void* callback; u8 opaque[0x38]; } DVDFileInfo;
typedef struct { void* entry; void* argument; void* stack; } OSThread;
typedef struct { OSMessage* messages; int capacity; } OSMessageQueue;
#define TRUE 1
#define FALSE 0
#define OS_MESSAGE_BLOCK 1
#define STATIC_ASSERT(...)
'''
PROTOTYPES = r'''
static BOOL OSCreateThread(OSThread*, void* (*)(void*), void*, void*, u32, OSPriority, u16);
static void OSInitMessageQueue(OSMessageQueue*, void*, s32);
static int OSReceiveMessage(OSMessageQueue*, void*, s32);
static int OSSendMessage(OSMessageQueue*, OSMessage, s32);
static void OSSuspendThread(OSThread*);
static void OSResumeThread(OSThread*);
static void OSCancelThread(OSThread*);
static s32 DVDReadPrio(DVDFileInfo*, void*, s32, s32, s32);
static void PrepareReady(int);
AttractMoviePlayer gAttractMoviePlayer;
'''
SERVICES = r'''
static int cases, createResult, creates, resumes, cancels, suspends, initQueues;
static int readyCalls, readyResult, received, readCalls, sent, count, running, escapeSuspend;
static int wrapperSends, wrapperReceives;
static OSMessageQueue* wrapperQueue;
static OSMessage wrapperMessage;
static OSPriority expectedPriority;
static jmp_buf exitThread;
static struct {
    u32 offset, size, nextSize;
    s32 result;
} plan[8];
static AttractMovieReadBuffer buffers[8];
static u32 storage[8][40];

static BOOL OSCreateThread(OSThread* thread, void* (*entry)(void*), void* argument,
                           void* stackTop, u32 size, OSPriority priority, u16 flags) {
    assert(thread == &gAttractMovieReadThread && entry == THPRead_Reader && argument == NULL);
    assert(stackTop == gAttractMovieReadThreadStack + sizeof(gAttractMovieReadThreadStack));
    assert(size == 4096 && priority == expectedPriority && flags == 1);
    assert((uintptr_t)thread > UINT32_MAX && (uintptr_t)stackTop > UINT32_MAX);
    creates++; return createResult;
}
static void OSInitMessageQueue(OSMessageQueue* queue, void* messages, s32 capacity) {
    assert(capacity == 10 && initQueues < 3);
    OSMessageQueue* queues[] = {&gAttractMovieReadFreeQueue, &gAttractMovieReadDvdQueue,
                               &gAttractMovieReadAudioDecodedQueue};
    OSMessage* slots[] = {gAttractMovieReadFreeMessages, gAttractMovieReadDvdMessages,
                         gAttractMovieReadAudioDecodedMessages};
    assert(queue == queues[initQueues] && messages == slots[initQueues]);
    assert((uintptr_t)messages > UINT32_MAX);
    queue->messages = messages; queue->capacity = capacity; initQueues++;
}
static int OSReceiveMessage(OSMessageQueue* queue, void* destination, s32 flags) {
    assert(flags == OS_MESSAGE_BLOCK);
    OSMessage message;
    if (running) {
        assert(queue == &gAttractMovieReadFreeQueue && received == sent);
        if (received == count) longjmp(exitThread, 1);
        message = &buffers[received++];
    } else {
        assert(queue == wrapperQueue); message = wrapperMessage; wrapperReceives++;
    }
    memcpy(destination, &message, sizeof(message));
    return 1;
}
static int OSSendMessage(OSMessageQueue* queue, OSMessage message, s32 flags) {
    assert(flags == OS_MESSAGE_BLOCK);
    if (running) {
        assert(queue == &gAttractMovieReadDvdQueue && sent < count);
        assert(readCalls == sent + 1 && message == &buffers[sent]);
        assert(buffers[sent].frameNumber == sent);
        sent++;
    } else {
        assert(queue == wrapperQueue && message == wrapperMessage); wrapperSends++;
    }
    return 0; /* The SDK send result is intentionally ignored. */
}
static void OSSuspendThread(OSThread* thread) {
    assert(thread == &gAttractMovieReadThread); suspends++;
    if (escapeSuspend) longjmp(exitThread, 2);
}
static void OSResumeThread(OSThread* thread) { assert(thread == &gAttractMovieReadThread); resumes++; }
static void OSCancelThread(OSThread* thread) { assert(thread == &gAttractMovieReadThread); cancels++; }
static s32 DVDReadPrio(DVDFileInfo* file, void* destination, s32 size, s32 offset, s32 priority) {
    assert(file == &gAttractMoviePlayer.fileInfo && priority == 2 && readCalls < count);
    int i = readCalls++;
    assert(received == readCalls && sent == i);
    assert(destination == buffers[i].ptr && (uintptr_t)destination > UINT32_MAX);
    assert((u32)size == plan[i].size && (u32)offset == plan[i].offset);
    if (plan[i].result >= 0) ((u32*)destination)[0] = plan[i].nextSize;
    return plan[i].result;
}
static void PrepareReady(int ready) { readyCalls++; readyResult = ready; assert(ready == 0); }
'''
CHECKS = r'''
static void reset(void) {
    memset(&gAttractMoviePlayer, 0, sizeof(gAttractMoviePlayer));
    memset(plan, 0, sizeof(plan)); memset(storage, 0xa5, sizeof(storage));
    for (int i = 0; i < 8; i++) buffers[i] = (AttractMovieReadBuffer){(u8*)storage[i],-999};
    gAttractMovieReadThreadCreated = 0;
    createResult = 1; expectedPriority = 8;
    creates = resumes = cancels = suspends = initQueues = readyCalls = 0;
    received = readCalls = sent = count = running = 0;
    wrapperSends = wrapperReceives = 0; wrapperQueue = NULL; wrapperMessage = NULL;
    readyResult = -1; escapeSuspend = 1;
    cases++;
}
static void lifecycle(void) {
    for (int success = 0; success <= 1; success++) for (int priority = 8; priority <= 15; priority += 7) {
        reset(); createResult = success; expectedPriority = priority;
        ReadThreadStart(); ReadThreadCancel(); assert(!resumes && !cancels);
        assert(CreateReadThread(priority) == success && creates == 1);
        assert(initQueues == (success ? 3 : 0) && gAttractMovieReadThreadCreated == success);
        ReadThreadStart(); ReadThreadCancel(); ReadThreadCancel(); ReadThreadStart();
        assert(resumes == success && cancels == success && !gAttractMovieReadThreadCreated);
    }
    reset(); wrapperMessage = &buffers[5]; wrapperQueue = &gAttractMovieReadAudioDecodedQueue;
    PushReadedBuffer2(wrapperMessage); assert(PopReadedBuffer2() == wrapperMessage);
    wrapperQueue = &gAttractMovieReadDvdQueue; assert(PopReadedBuffer() == wrapperMessage);
    wrapperQueue = &gAttractMovieReadFreeQueue; PushFreeReadBuffer(wrapperMessage);
    assert(wrapperSends == 2 && wrapperReceives == 2);
}
static void addRead(u32 offset, u32 size, u32 nextSize) {
    assert(count < 8);
    plan[count].offset = offset; plan[count].size = size;
    plan[count].nextSize = nextSize; plan[count].result = size;
    storage[count][0] = nextSize; count++;
}
static int runReader(void) {
    running = 1;
    int reason = setjmp(exitThread);
    if (!reason) THPRead_Reader(NULL);
    running = 0;
    for (int i = 0; i < 8; i++) for (int j = 1; j < 40; j++) assert(storage[i][j] == 0xa5a5a5a5);
    return reason;
}
static void progression(void) {
    for (int loop = 0; loop <= 1; loop++) for (int initial = 0; initial <= 2; initial++) {
        reset();
        static const u32 offsets[] = {0x2000,0x2040,0x20a0};
        static const u32 sizes[] = {64,96,80};
        gAttractMoviePlayer.header.mNumFrames = 3;
        gAttractMoviePlayer.header.mMovieDataOffsets = 0x2000;
        gAttractMoviePlayer.initOffset = offsets[initial];
        gAttractMoviePlayer.initReadFrame = initial;
        gAttractMoviePlayer.initReadSize = sizes[initial];
        gAttractMoviePlayer.playFlags = loop;
        int frames = loop ? 7 : 3-initial;
        for (int i = 0; i < frames; i++) {
            int frame = (initial+i)%3;
            addRead(offsets[frame],sizes[frame],sizes[(frame+1)%3]);
        }
        assert(runReader() == (loop ? 1 : 2));
        assert(readCalls == frames && sent == frames && !readyCalls);
        assert(suspends == !loop && !gAttractMoviePlayer.dvdError);
    }
    /* Frame numbers are relative to the requested start, including a one-frame movie. */
    reset();
    gAttractMoviePlayer.header.mNumFrames = 1;
    gAttractMoviePlayer.initOffset = 0x1000; gAttractMoviePlayer.initReadSize = 32;
    addRead(0x1000,32,32);
    assert(runReader() == 2 && readCalls == 1 && sent == 1 && buffers[0].frameNumber == 0);
    /* File positions are 32-bit values, not host addresses. */
    reset(); escapeSuspend = 0;
    gAttractMoviePlayer.header.mNumFrames = 4;
    gAttractMoviePlayer.initOffset = (s32)0xfffffff0u; gAttractMoviePlayer.initReadSize = 64;
    addRead(0xfffffff0u,64,32); addRead(0x30,32,64);
    assert(runReader() == 1 && readCalls == 2 && sent == 2 && !suspends);
}
static void failures(void) {
    static const s32 results[] = {-1,-2,0,31,95};
    for (int at = 0; at <= 1; at++) for (size_t r = 0; r < sizeof(results)/sizeof(results[0]); r++) {
        reset();
        gAttractMoviePlayer.header.mNumFrames = 4;
        gAttractMoviePlayer.header.mMovieDataOffsets = 0x2000;
        gAttractMoviePlayer.initOffset = 0x2040; gAttractMoviePlayer.initReadSize = 96;
        gAttractMoviePlayer.initReadFrame = 1;
        gAttractMoviePlayer.dvdError = 17;
        addRead(0x2040,96,80); addRead(0x20a0,80,64);
        plan[at].result = results[r];
        assert(runReader() == 2);
        assert(readCalls == at+1 && sent == at && received == at+1 && suspends == 1);
        assert(buffers[at].frameNumber == -999);
        assert(readyCalls == !at && readyResult == (at ? -1 : 0));
        assert(gAttractMoviePlayer.dvdError == (results[r] == -1 ? -1 : 17));
    }
    /* If resumed after an error, retail continues with that buffer and next-size word. */
    reset(); escapeSuspend = 0;
    gAttractMoviePlayer.header.mNumFrames = 4;
    gAttractMoviePlayer.initOffset = 0x2000; gAttractMoviePlayer.initReadSize = 64;
    addRead(0x2000,64,96); addRead(0x2040,96,80);
    plan[0].result = -1;
    assert(runReader() == 1 && sent == 2 && readCalls == 2 && suspends == 1);
    assert(readyCalls == 1 && readyResult == 0 && gAttractMoviePlayer.dvdError == -1);
    /* A resumed non-looping final frame continues; suspension is the actual stop. */
    reset(); escapeSuspend = 0;
    gAttractMoviePlayer.header.mNumFrames = 1;
    gAttractMoviePlayer.initOffset = 0x2000; gAttractMoviePlayer.initReadSize = 64;
    addRead(0x2000,64,96); addRead(0x2040,96,80);
    assert(runReader() == 1 && sent == 2 && suspends == 2 && !readyCalls);
}
int main(void) {
    assert(sizeof(void*) == 8 && (uintptr_t)buffers > UINT32_MAX);
    assert((uintptr_t)&gAttractMoviePlayer > UINT32_MAX);
    lifecycle(); progression(); failures();
    printf("%d complete-TU THP reader scenarios passed with native pointers\n",cases);
}
'''


def without_includes(path):
    return re.sub(r'^#include[^\n]*\n', '', (ROOT / path).read_text(), flags=re.M)


def harness():
    records = '\n'.join(without_includes(path) for path in [
        'include/dolphin/thp/THPFile.h', 'include/dolphin/thp/THPInfo.h',
        'include/main/dll/FRONT/attract_movie.h', 'include/main/thp_read.h'])
    return '\n'.join([PRELUDE, records, PROTOTYPES,
                      without_includes('src/main/thp/THPRead.c'), SERVICES, CHECKS])


class THPReadNativeTest(unittest.TestCase):
    def test_complete_tu(self):
        compiler = shutil.which('clang') or shutil.which('cc')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='thp-read-') as directory:
            path = Path(directory)
            source = path / 'read.c'
            source.write_text(harness())
            for optimization in ['-O0', '-O2']:
                with self.subTest(optimization=optimization):
                    exe = path / 'read'
                    subprocess.run([compiler, '-std=c11', optimization, '-g', '-Wall', '-Wextra',
                                    '-Werror', '-Wno-unused-parameter', '-fsanitize=address,undefined',
                                    '-fno-omit-frame-pointer', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
