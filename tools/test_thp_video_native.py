#!/usr/bin/env python3
"""Run the complete production video-thread TU with independent native OS objects.

The SDK adapters deliberately use host-sized queues and thread objects. This
catches aliases that rely on the retail linker placing unrelated globals nearby.
"""
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
typedef struct { void* callback; u8 opaque[0x38]; } DVDFileInfo;
typedef struct { void* entry; void* argument; void* stack; } OSThread;
typedef struct { void* messages; int capacity; } OSMessageQueue;
#define TRUE 1
#define FALSE 0
#define OS_MESSAGE_BLOCK 1
#define OS_MESSAGE_NOBLOCK 0
#define STATIC_ASSERT(...)
'''
PROTOTYPES = r'''
static BOOL OSCreateThread(OSThread*, void* (*)(void*), void*, void*, u32, OSPriority, u16);
static void OSInitMessageQueue(OSMessageQueue*, void*, s32);
static int OSReceiveMessage(OSMessageQueue*, OSMessage*, s32);
static int OSSendMessage(OSMessageQueue*, OSMessage, s32);
static void OSSuspendThread(OSThread*);
static void OSResumeThread(OSThread*);
static void OSCancelThread(OSThread*);
static u32 OSDisableInterrupts(void);
static void OSRestoreInterrupts(u32);
static s32 THPVideoDecode(void*, void*, void*, void*, void*);
static void PrepareReady(int);
static AttractMovieReadBuffer* PopReadedBuffer(void);
static AttractMovieReadBuffer* PopReadedBuffer2(void);
static void PushFreeReadBuffer(AttractMovieReadBuffer*);
AttractMoviePlayer gAttractMoviePlayer;
'''
SERVICES = r'''
static int cases, createResult, creates, resumes, cancels, suspends, initQueues, interrupts;
static int decodeCalls, freeReceives, sentDecoded, sentFree, readyCalls, readyResult;
static int freeReceiveLimit, escapeSuspend, expectedDecodeCount;
static int readCount, readIndex, returnedReads, regularPops, audioPops;
static int receiveResult, receiveFlags, sendFlags;
static OSMessage receivedMessage, sentMessage;
static AttractMovieReadBuffer records[8];
static AttractMovieTextureSet textures[3];
static u8 planes[3][3][32], work[64];
static u32 movie[64];
static u32 packet[32];
static u8* expectedData[8];
static s32 decodeResults[8], decodedFrames[8];
static void* (*threadEntry)(void*);
static void* threadArgument;
static jmp_buf exitThread;

static BOOL OSCreateThread(OSThread* thread, void* (*entry)(void*), void* argument,
                           void* stackTop, u32 size, OSPriority priority, u16 flags) {
    assert(thread == &gAttractMovieVideoThread && priority == 15 && flags == 1);
    assert(stackTop == gAttractMovieVideoThreadStack + sizeof(gAttractMovieVideoThreadStack));
    assert(size == 4096 && (uintptr_t)thread > UINT32_MAX && (uintptr_t)stackTop > UINT32_MAX);
    threadEntry = entry; threadArgument = argument; creates++; return createResult;
}
static void OSInitMessageQueue(OSMessageQueue* queue, void* messages, s32 count) {
    assert(count == 3 && initQueues < 2);
    if (initQueues == 0) {
        assert(queue == &gAttractMovieVideoFreeTextureSetQueue && messages == gAttractMovieVideoFreeMessages);
    } else {
        assert(queue == &gAttractMovieVideoDecodedTextureSetQueue && messages == gAttractMovieVideoDecodedMessages);
    }
    assert((uintptr_t)messages > UINT32_MAX);
    queue->messages = messages; queue->capacity = count; initQueues++;
}
static int OSReceiveMessage(OSMessageQueue* queue, OSMessage* message, s32 flags) {
    if (queue == &gAttractMovieVideoFreeTextureSetQueue) {
        assert(flags == OS_MESSAGE_BLOCK);
        if (freeReceives == freeReceiveLimit) longjmp(exitThread, 1);
        *message = &textures[freeReceives++ % 3]; return 1;
    }
    assert(queue == &gAttractMovieVideoDecodedTextureSetQueue);
    *message = receivedMessage; receiveFlags = flags; return receiveResult;
}
static int OSSendMessage(OSMessageQueue* queue, OSMessage message, s32 flags) {
    if (queue == &gAttractMovieVideoDecodedTextureSetQueue) {
        assert(flags == OS_MESSAGE_BLOCK && sentDecoded < 8);
        assert(message == &textures[(freeReceives - 1) % 3]);
        decodedFrames[sentDecoded++] = ((AttractMovieTextureSet*)message)->frameNumber;
    } else {
        assert(queue == &gAttractMovieVideoFreeTextureSetQueue);
        sentFree++; sentMessage = message; sendFlags = flags;
    }
    return 0; /* Production deliberately ignores the send result. */
}
static void OSSuspendThread(OSThread* thread) {
    assert(thread == &gAttractMovieVideoThread); suspends++;
    if (escapeSuspend) longjmp(exitThread, 2);
}
static void OSResumeThread(OSThread* thread) { assert(thread == &gAttractMovieVideoThread); resumes++; }
static void OSCancelThread(OSThread* thread) { assert(thread == &gAttractMovieVideoThread); cancels++; }
static u32 OSDisableInterrupts(void) { assert(!interrupts); interrupts = 1; return 31; }
static void OSRestoreInterrupts(u32 previous) { assert(previous == 31 && interrupts == 1); interrupts = 0; }
static s32 THPVideoDecode(void* data, void* y, void* u, void* v, void* workspace) {
    assert(decodeCalls < expectedDecodeCount && data == expectedData[decodeCalls]);
    int texture = (freeReceives - 1) % 3;
    assert(y == planes[texture][0] && u == planes[texture][1] && v == planes[texture][2]);
    assert(workspace == work && (uintptr_t)data > UINT32_MAX);
    return decodeResults[decodeCalls++];
}
static void PrepareReady(int ready) { readyCalls++; readyResult = ready; }
static AttractMovieReadBuffer* nextRead(void) {
    if (readIndex == readCount) longjmp(exitThread, 3);
    return &records[readIndex++];
}
static AttractMovieReadBuffer* PopReadedBuffer(void) { regularPops++; return nextRead(); }
static AttractMovieReadBuffer* PopReadedBuffer2(void) { audioPops++; return nextRead(); }
static void PushFreeReadBuffer(AttractMovieReadBuffer* record) {
    assert(record == &records[returnedReads++]);
}
'''
CHECKS = r'''
static void reset(void) {
    memset(&gAttractMoviePlayer, 0, sizeof(gAttractMoviePlayer));
    memset(movie, 0, sizeof(movie)); memset(packet, 0, sizeof(packet));
    memset(decodeResults, 0, sizeof(decodeResults)); memset(decodedFrames, 0, sizeof(decodedFrames));
    for (int i = 0; i < 3; i++) {
        textures[i] = (AttractMovieTextureSet){planes[i][0], planes[i][1], planes[i][2], -1};
    }
    creates = resumes = cancels = suspends = initQueues = interrupts = 0;
    decodeCalls = freeReceives = sentDecoded = sentFree = readyCalls = readyResult = 0;
    readCount = readIndex = returnedReads = regularPops = audioPops = 0;
    receiveFlags = sendFlags = -1; receivedMessage = sentMessage = NULL;
    createResult = receiveResult = 1; freeReceiveLimit = 8; escapeSuspend = 0;
    gAttractMovieVideoThreadCreated = gAttractMovieVideoPrepareReady = 0;
    gAttractMovieIdleFrameCount = 99;
    gAttractMoviePlayer.thpWorkArea = work;
    expectedDecodeCount = 0;
    cases++;
}
static void checkThreadLifecycle(void) {
    for (int memory = 0; memory <= 1; memory++) for (int success = 0; success <= 1; success++) {
        reset(); createResult = success;
        VideoDecodeThreadStart(); VideoDecodeThreadCancel(); assert(!resumes && !cancels);
        void* argument = memory ? movie : NULL;
        assert(CreateVideoDecodeThread(15, argument) == success && creates == 1);
        assert(threadArgument == argument);
        assert(threadEntry == (memory ? AttractMovieVideo_DecoderForOnMemory : AttractMovieVideo_Decoder));
        assert(gAttractMovieVideoThreadCreated == success && gAttractMovieVideoPrepareReady == success);
        assert(initQueues == (success ? 2 : 0));
        VideoDecodeThreadStart(); VideoDecodeThreadCancel(); VideoDecodeThreadCancel();
        VideoDecodeThreadStart(); assert(resumes == success && cancels == success);
        assert(!gAttractMovieVideoThreadCreated);
    }
    reset(); receivedMessage = &textures[2];
    assert(PopDecodedTextureSet(0) == receivedMessage && receiveFlags == 0);
    receiveResult = 0; assert(PopDecodedTextureSet(1) == NULL && receiveFlags == 1);
    PushFreeTextureSet(&textures[1]);
    assert(sentFree == 1 && sentMessage == &textures[1] && sendFlags == OS_MESSAGE_NOBLOCK);
}
static void checkDecode(void) {
    for (int ready = 0; ready <= 1; ready++) for (int fail = 0; fail <= 1; fail++) {
        reset(); gAttractMovieVideoPrepareReady = ready;
        gAttractMoviePlayer.compInfo = (THPFrameCompInfo){.mNumComponents=3, .mFrameComp={1,0,7}};
        packet[2] = 12; packet[3] = 20; packet[4] = 4;
        expectedData[0] = (u8*)packet + 32; expectedDecodeCount = 1;
        decodeResults[0] = fail ? -17 : 0;
        AttractMovieReadBuffer buffer = {(u8*)packet, 73};
        AttractMovieVideo_Decode(&buffer);
        assert(decodeCalls == 1 && sentDecoded == 1 && decodedFrames[0] == 73);
        assert(gAttractMoviePlayer.videoDecodeCount == 1 && !interrupts && gAttractMovieIdleFrameCount == 0);
        assert(gAttractMoviePlayer.videoError == decodeResults[0] && suspends == fail);
        assert(readyCalls == ready && readyResult == (ready && !fail) && !gAttractMovieVideoPrepareReady);
    }
    reset(); gAttractMovieVideoPrepareReady = 1;
    gAttractMoviePlayer.compInfo = (THPFrameCompInfo){.mNumComponents=1, .mFrameComp={1}};
    packet[2] = 8; AttractMovieReadBuffer buffer = {(u8*)packet, -1};
    AttractMovieVideo_Decode(&buffer);
    assert(!decodeCalls && !sentDecoded && gAttractMovieIdleFrameCount == 99);
    assert(readyCalls == 1 && readyResult == 1 && !gAttractMovieVideoPrepareReady);
    reset(); gAttractMovieVideoPrepareReady = 1;
    gAttractMoviePlayer.compInfo = (THPFrameCompInfo){.mNumComponents=2, .mFrameComp={0,0}};
    packet[2] = 12; packet[3] = 8;
    expectedData[0] = (u8*)packet + 16; expectedData[1] = (u8*)packet + 28; expectedDecodeCount = 2;
    AttractMovieVideo_Decode(&buffer);
    assert(decodeCalls == 2 && sentDecoded == 2 && decodedFrames[0] == -1 && decodedFrames[1] == -1);
    assert(gAttractMoviePlayer.videoDecodeCount == 2 && readyCalls == 1 && readyResult == 1);
}
static const int offsets[3] = {0,64,160};
static const int sizes[3] = {64,96,80};
static void movieSetup(int audio, int lag, int loop, int initialFrame) {
    reset();
    gAttractMoviePlayer.audioExists = audio; gAttractMoviePlayer.videoDecodeCount = lag;
    gAttractMoviePlayer.playFlags = loop;
    gAttractMoviePlayer.header.mNumFrames = 3;
    gAttractMoviePlayer.initReadFrame = initialFrame;
    gAttractMoviePlayer.initReadSize = sizes[initialFrame];
    gAttractMoviePlayer.movieData = (u8*)movie;
    gAttractMoviePlayer.compInfo = (THPFrameCompInfo){.mNumComponents=1, .mFrameComp={0}};
    gAttractMovieVideoPrepareReady = 1;
    for (int i = 0; i < 3; i++) {
        movie[offsets[i]/4] = sizes[(i+1)%3];
        movie[offsets[i]/4+2] = 16;
    }
}
static void checkMemory(void) {
    static const struct {
        int audio, lag, loop, initial, count, finalCount, stop;
        int frames[5];
    } table[] = {
        {0,0,0,0,3,3,2,{0,1,2}}, {1,0,0,0,3,3,2,{0,1,2}},
        {0,0,1,0,5,5,1,{0,1,2,3,4}}, {1,-1,1,0,4,4,1,{1,2,3,4}},
        {1,-4,1,0,3,3,1,{4,5,6}}, {1,-4,0,0,1,0,2,{2}},
        {0,0,0,1,2,2,2,{0,1}}, {1,-1,0,2,1,1,2,{0}}
    };
    for (size_t t = 0; t < sizeof(table)/sizeof(table[0]); t++) {
        movieSetup(table[t].audio,table[t].lag,table[t].loop,table[t].initial);
        expectedDecodeCount = freeReceiveLimit = table[t].count;
        for (int i = 0; i < expectedDecodeCount; i++) {
            int frame = (table[t].frames[i] + table[t].initial)%3;
            expectedData[i] = (u8*)movie + offsets[frame] + 12;
        }
        escapeSuspend = 1;
        int reason = setjmp(exitThread);
        if (!reason) AttractMovieVideo_DecoderForOnMemory((u8*)movie + offsets[table[t].initial]);
        assert(reason == table[t].stop && decodeCalls == table[t].count && sentDecoded == table[t].count);
        for (int i = 0; i < sentDecoded; i++) assert(decodedFrames[i] == table[t].frames[i]);
        assert(gAttractMoviePlayer.videoDecodeCount == table[t].finalCount);
        assert(readyCalls == 1 && readyResult == 1 && !interrupts);
    }
}
static void checkStreaming(void) {
    static const struct {
        int audio, lag, loop, initial, reads, count, finalCount;
        int frames[4];
    } table[] = {
        {0,0,0,0,3,3,3,{0,1,2}}, {1,0,0,0,3,3,3,{0,1,2}},
        {1,-2,1,0,4,2,2,{2,3}}, {1,-5,0,0,3,1,-1,{2}},
        {1,-2,0,1,3,2,2,{1,2}}
    };
    for (size_t t = 0; t < sizeof(table)/sizeof(table[0]); t++) {
        movieSetup(table[t].audio,table[t].lag,table[t].loop,table[t].initial);
        readCount = table[t].reads; expectedDecodeCount = table[t].count;
        for (int i = 0; i < readCount; i++) records[i] = (AttractMovieReadBuffer){(u8*)movie+offsets[i%3],i};
        for (int i = 0; i < expectedDecodeCount; i++) expectedData[i] = records[table[t].frames[i]].ptr + 12;
        int reason = setjmp(exitThread);
        if (!reason) AttractMovieVideo_Decoder(NULL);
        assert(reason == 3 && returnedReads == readCount && decodeCalls == table[t].count);
        for (int i = 0; i < sentDecoded; i++) assert(decodedFrames[i] == table[t].frames[i]);
        assert((table[t].audio ? audioPops : regularPops) == readCount + 1);
        assert((table[t].audio ? regularPops : audioPops) == 0);
        assert(gAttractMoviePlayer.videoDecodeCount == table[t].finalCount && !interrupts);
        assert(readyCalls == 1 && readyResult == 1);
    }
}
int main(void) {
    assert(sizeof(void*) == 8 && (uintptr_t)&gAttractMoviePlayer > UINT32_MAX);
    assert((uintptr_t)movie > UINT32_MAX);
    checkThreadLifecycle(); checkDecode(); checkMemory(); checkStreaming();
    printf("%d complete-TU video-thread scenarios passed with native pointers\n",cases);
}
'''


def without_includes(path):
    return re.sub(r'^#include[^\n]*\n', '', (ROOT / path).read_text(), flags=re.M)


def harness():
    records = '\n'.join(without_includes(path) for path in [
        'include/dolphin/thp/THPFile.h', 'include/dolphin/thp/THPInfo.h',
        'include/main/dll/FRONT/attract_movie.h', 'include/main/thp_video_decode.h'])
    return '\n'.join([PRELUDE, records, PROTOTYPES,
                      without_includes('src/main/thp/THPVideoDecode.c'), SERVICES, CHECKS])


class THPVideoNativeTest(unittest.TestCase):
    def test_complete_tu(self):
        compiler = shutil.which('clang') or shutil.which('cc')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='thp-video-') as directory:
            path = Path(directory)
            source = path / 'video.c'
            source.write_text(harness())
            for optimization in ['-O0', '-O2']:
                with self.subTest(optimization=optimization):
                    exe = path / 'video'
                    subprocess.run([compiler, '-std=c11', optimization, '-g', '-Wall', '-Wextra',
                                    '-Werror', '-Wno-unused-parameter', '-fsanitize=address,undefined',
                                    '-fno-omit-frame-pointer', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
