#!/usr/bin/env python3
"""Exercise the complete THP audio TU with native records and independent OS objects."""
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
#include <stdbool.h>
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
typedef struct { OSMessage* messages; int capacity; } OSMessageQueue;
#define OS_MESSAGE_NOBLOCK 0
#define OS_MESSAGE_BLOCK 1
#define ARRAY_COUNT(a) (sizeof(a)/sizeof((a)[0]))
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
static u32 THPAudioDecode(s16*, u8*, int);
static AttractMovieReadBuffer* PopReadedBuffer(void);
static void PushReadedBuffer2(AttractMovieReadBuffer*);
AttractMoviePlayer gAttractMoviePlayer;
'''
SERVICES = r'''
static int cases, createResult, creates, resumes, cancels, suspends, initQueues;
static int receives, receiveLimit, decoded, posted, expectedCount, escapeSuspend;
static int readCount, readIndex, forwarded, streaming;
static int wrapperFlags, wrapperResult, wrapperSends;
static OSMessage wrapperMessage;
static OSPriority expectedPriority;
static void* (*threadEntry)(void*);
static void* threadArgument;
static AttractMovieReadBuffer records[8];
static AttractMovieAudioBuffer buffers[3];
static s16 samples[3][18];
static u32 movie[64], packet[32];
static u8* expectedData[8];
static u32 expectedSamples[8];
static s32 expectedFrames[8];
static jmp_buf exitThread;

static BOOL OSCreateThread(OSThread* thread, void* (*entry)(void*), void* argument,
                           void* stackTop, u32 size, OSPriority priority, u16 flags) {
    assert(thread == &gAttractMovieAudioDecodeThread && priority == expectedPriority && flags == 1);
    assert(stackTop == gAttractMovieAudioDecodeThreadStack + sizeof(gAttractMovieAudioDecodeThreadStack));
    assert(size == 4096 && (uintptr_t)thread > UINT32_MAX && (uintptr_t)stackTop > UINT32_MAX);
    threadEntry = entry; threadArgument = argument; creates++; return createResult;
}
static void OSInitMessageQueue(OSMessageQueue* queue, void* messages, s32 count) {
    assert(count == 3 && initQueues < 2);
    if (initQueues == 0) {
        assert(queue == &gAttractMovieFreeAudioQueue && messages == gAttractMovieAudioFreeMessages);
    } else {
        assert(queue == &gAttractMovieDecodedAudioQueue && messages == gAttractMovieAudioDecodedMessages);
    }
    assert((uintptr_t)messages > UINT32_MAX);
    queue->messages = messages; queue->capacity = count; initQueues++;
}
static int OSReceiveMessage(OSMessageQueue* queue, void* destination, s32 flags) {
    OSMessage message;
    if (queue == &gAttractMovieFreeAudioQueue) {
        assert(flags == OS_MESSAGE_BLOCK);
        if (receives == receiveLimit) longjmp(exitThread, 1);
        message = &buffers[receives++ % 3];
        memcpy(destination, &message, sizeof(message)); return 1;
    }
    assert(queue == &gAttractMovieDecodedAudioQueue);
    wrapperFlags = flags;
    memcpy(destination, &wrapperMessage, sizeof(wrapperMessage)); return wrapperResult;
}
static int OSSendMessage(OSMessageQueue* queue, OSMessage message, s32 flags) {
    if (queue == &gAttractMovieDecodedAudioQueue) {
        assert(flags == OS_MESSAGE_BLOCK && posted < expectedCount && decoded == posted + 1);
        AttractMovieAudioBuffer* buffer = &buffers[(receives - 1) % 3];
        assert(message == buffer && buffer->curPtr == buffer->buffer);
        assert(buffer->validSample == expectedSamples[posted] && buffer->frameNumber == expectedFrames[posted]);
        assert(buffer->buffer[0] == 123 && buffer->buffer[15] == -123);
        posted++;
    } else {
        assert(queue == &gAttractMovieFreeAudioQueue && message == wrapperMessage);
        wrapperSends++; wrapperFlags = flags;
    }
    return 0; /* Retail ignores send results. */
}
static void OSSuspendThread(OSThread* thread) {
    assert(thread == &gAttractMovieAudioDecodeThread); suspends++;
    if (escapeSuspend) longjmp(exitThread, 2);
}
static void OSResumeThread(OSThread* thread) { assert(thread == &gAttractMovieAudioDecodeThread); resumes++; }
static void OSCancelThread(OSThread* thread) { assert(thread == &gAttractMovieAudioDecodeThread); cancels++; }
static u32 THPAudioDecode(s16* output, u8* data, int flag) {
    assert(decoded < expectedCount && data == expectedData[decoded] && flag == 0);
    assert(output == buffers[(receives - 1) % 3].buffer);
    assert((uintptr_t)data > UINT32_MAX && (uintptr_t)output > UINT32_MAX);
    if (streaming) assert(forwarded == decoded && readIndex == decoded + 1);
    output[0] = 123; output[15] = -123;
    return expectedSamples[decoded++];
}
static AttractMovieReadBuffer* PopReadedBuffer(void) {
    if (readIndex == readCount) longjmp(exitThread, 3);
    return &records[readIndex++];
}
static void PushReadedBuffer2(AttractMovieReadBuffer* record) {
    assert(record == &records[forwarded] && readIndex == forwarded + 1);
    assert(posted == forwarded + 1); forwarded++;
}
'''
CHECKS = r'''
static void reset(void) {
    memset(&gAttractMoviePlayer, 0, sizeof(gAttractMoviePlayer));
    memset(movie, 0xa5, sizeof(movie)); memset(packet, 0xa5, sizeof(packet));
    memset(samples, 0x5a, sizeof(samples));
    for (int i = 0; i < 3; i++) buffers[i] = (AttractMovieAudioBuffer){samples[i]+1,NULL,999,-999};
    for (int i = 0; i < 8; i++) { expectedSamples[i] = 32+i; expectedFrames[i] = i; }
    creates = resumes = cancels = suspends = initQueues = 0;
    receives = decoded = posted = expectedCount = 0;
    readCount = readIndex = forwarded = streaming = wrapperSends = 0;
    createResult = wrapperResult = 1; wrapperFlags = -1; wrapperMessage = NULL;
    receiveLimit = 8; escapeSuspend = 1; expectedPriority = 15;
    gAttractMovieAudioThreadActive = 0; threadEntry = NULL; threadArgument = NULL;
    cases++;
}
static void checkCanaries(void) {
    for (int i = 0; i < 3; i++) {
        assert(samples[i][0] == 0x5a5a && samples[i][17] == 0x5a5a);
        for (int j = 2; j < 16; j++) assert(samples[i][j] == 0x5a5a);
        assert(buffers[i].buffer == samples[i]+1);
    }
}
static void lifecycle(void) {
    for (int memory = 0; memory <= 1; memory++) for (int success = 0; success <= 1; success++) {
        for (int priority = 8; priority <= 15; priority += 7) {
            reset(); createResult = success; expectedPriority = priority;
            AudioDecodeThreadStart(); AudioDecodeThreadCancel(); assert(!resumes && !cancels);
            void* argument = memory ? movie : NULL;
            assert(CreateAudioDecodeThread(priority, argument) == success && creates == 1);
            assert(threadArgument == argument);
            assert(threadEntry == (memory ? AudioDecoderForOnMemory : AudioDecoder));
            assert(gAttractMovieAudioThreadActive == success && initQueues == (success ? 2 : 0));
            AudioDecodeThreadStart(); AudioDecodeThreadCancel(); AudioDecodeThreadCancel(); AudioDecodeThreadStart();
            assert(resumes == success && cancels == success && !gAttractMovieAudioThreadActive);
        }
    }
    reset(); wrapperMessage = &buffers[2];
    assert(PopDecodedAudioBuffer(0) == wrapperMessage && wrapperFlags == 0);
    wrapperResult = 0; assert(PopDecodedAudioBuffer(1) == NULL && wrapperFlags == 1);
    wrapperResult = -1; assert(PopDecodedAudioBuffer(0) == NULL);
    PushFreeAudioBuffer(wrapperMessage); assert(wrapperSends == 1 && wrapperFlags == OS_MESSAGE_NOBLOCK);
}
static void componentTraversal(void) {
    for (int audioPosition = 0; audioPosition < 3; audioPosition++) {
        for (int zeroSamples = 0; zeroSamples <= 1; zeroSamples++) {
            reset();
            gAttractMoviePlayer.compInfo = (THPFrameCompInfo){.mNumComponents=3, .mFrameComp={7,0,9}};
            gAttractMoviePlayer.compInfo.mFrameComp[audioPosition] = 1;
            packet[2] = 12; packet[3] = 20; packet[4] = 4;
            const int offsets[] = {20,32,52};
            expectedData[0] = (u8*)packet + offsets[audioPosition];
            expectedSamples[0] = zeroSamples ? 0 : UINT32_MAX;
            expectedFrames[0] = -17; expectedCount = 1;
            AttractMovieReadBuffer record = {(u8*)packet,-17};
            AttractMovieAudio_Decode(&record);
            assert(decoded == 1 && posted == 1 && receives == 1 && !suspends); checkCanaries();
        }
    }
    /* The retail component loop posts the same buffer again if audio appears twice. */
    reset(); gAttractMoviePlayer.compInfo = (THPFrameCompInfo){.mNumComponents=2,.mFrameComp={1,1}};
    packet[2] = 12; packet[3] = 20;
    expectedCount = 2; expectedData[0] = (u8*)packet+16; expectedData[1] = (u8*)packet+28;
    expectedFrames[0] = expectedFrames[1] = 73;
    AttractMovieReadBuffer record = {(u8*)packet,73};
    AttractMovieAudio_Decode(&record);
    assert(decoded == 2 && posted == 2 && receives == 1); checkCanaries();
    /* A frame without audio still consumes a free buffer and never posts it. */
    for (int components = 0; components <= 1; components++) {
        reset(); gAttractMoviePlayer.compInfo = (THPFrameCompInfo){.mNumComponents=components,.mFrameComp={0}};
        packet[2] = 12; AttractMovieAudio_Decode(&record);
        assert(!decoded && !posted && receives == 1 && !suspends); checkCanaries();
    }
}
static const int offsets[3] = {0,64,160};
static const int sizes[3] = {64,96,80};
static void movieSetup(int initial, int loop, int frames) {
    reset();
    gAttractMoviePlayer.header.mNumFrames = frames; gAttractMoviePlayer.playFlags = loop;
    gAttractMoviePlayer.initReadFrame = initial; gAttractMoviePlayer.initReadSize = sizes[initial];
    gAttractMoviePlayer.movieData = (u8*)movie;
    gAttractMoviePlayer.compInfo = (THPFrameCompInfo){.mNumComponents=1,.mFrameComp={1}};
    for (int i = 0; i < frames; i++) {
        movie[offsets[i]/4] = sizes[(i+1)%frames]; movie[offsets[i]/4+2] = 16;
    }
}
static void memoryPlayback(void) {
    for (int loop = 0; loop <= 1; loop++) for (int initial = 0; initial < 3; initial++) {
        movieSetup(initial,loop,3); expectedCount = receiveLimit = loop ? 7 : 3-initial;
        for (int i = 0; i < expectedCount; i++) expectedData[i] = (u8*)movie + offsets[(i+initial)%3] + 12;
        int reason = setjmp(exitThread);
        if (!reason) AudioDecoderForOnMemory((u8*)movie + offsets[initial]);
        assert(reason == (loop ? 1 : 2) && decoded == expectedCount && posted == expectedCount);
        assert(suspends == !loop && !forwarded); checkCanaries();
    }
    for (int loop = 0; loop <= 1; loop++) {
        movieSetup(0,loop,1); expectedCount = receiveLimit = loop ? 4 : 1;
        for (int i = 0; i < expectedCount; i++) expectedData[i] = (u8*)movie + 12;
        int reason = setjmp(exitThread);
        if (!reason) AudioDecoderForOnMemory(movie);
        assert(reason == (loop ? 1 : 2) && posted == expectedCount && suspends == !loop); checkCanaries();
    }
    /* Suspension is the stop: resuming a one-frame non-looping movie decodes it again. */
    movieSetup(0,0,1); expectedCount = receiveLimit = 3; escapeSuspend = 0;
    for (int i = 0; i < expectedCount; i++) expectedData[i] = (u8*)movie + 12;
    int reason = setjmp(exitThread);
    if (!reason) AudioDecoderForOnMemory(movie);
    assert(reason == 1 && posted == 3 && suspends == 3); checkCanaries();
}
static void streamingPlayback(void) {
    movieSetup(0,0,3); readCount = expectedCount = 7; streaming = 1;
    for (int i = 0; i < readCount; i++) {
        records[i] = (AttractMovieReadBuffer){(u8*)movie + offsets[i%3],i+91};
        expectedData[i] = records[i].ptr+12; expectedFrames[i] = i+91;
    }
    int reason = setjmp(exitThread);
    if (!reason) AudioDecoder(NULL);
    assert(reason == 3 && posted == 7 && forwarded == 7 && !suspends); checkCanaries();
}
int main(void) {
    assert(sizeof(void*) == 8 && (uintptr_t)&gAttractMoviePlayer > UINT32_MAX);
    assert((uintptr_t)movie > UINT32_MAX && (uintptr_t)buffers > UINT32_MAX);
    lifecycle(); componentTraversal(); memoryPlayback(); streamingPlayback();
    printf("%d complete-TU THP audio scenarios passed with native pointers\n",cases);
}
'''


def without_includes(path):
    return re.sub(r'^#include[^\n]*\n', '', (ROOT / path).read_text(), flags=re.M)


def harness():
    records = '\n'.join(without_includes(path) for path in [
        'include/dolphin/thp/THPFile.h', 'include/dolphin/thp/THPInfo.h',
        'include/main/dll/FRONT/attract_movie.h', 'include/main/audio_decode_thread.h'])
    return '\n'.join([PRELUDE, records, PROTOTYPES,
                      without_includes('src/main/thp/THPAudioDecode.c'), SERVICES, CHECKS])


class THPAudioNativeTest(unittest.TestCase):
    def test_complete_tu(self):
        compiler = shutil.which('clang') or shutil.which('cc')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='thp-audio-') as directory:
            path = Path(directory)
            source = path / 'audio.c'
            source.write_text(harness())
            for optimization in ['-O0', '-O2']:
                with self.subTest(optimization=optimization):
                    exe = path / 'audio'
                    subprocess.run([compiler, '-std=c11', optimization, '-g', '-Wall', '-Wextra',
                                    '-Werror', '-Wno-unused-parameter', '-fsanitize=address,undefined',
                                    '-fno-omit-frame-pointer', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
