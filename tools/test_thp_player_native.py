#!/usr/bin/env python3
"""Exercise production THP initialization, file parsing and preparation on a 64-bit host.

Only the DVD, audio, queue and thread services are replaced. The player records,
ordinary storage definitions and selected function bodies come from production.
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
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
typedef void* OSMessage;
typedef void (*AIDCallback)(void);
typedef void (*VIRetraceCallback)(u32);
typedef struct { void* callback; u8 opaque[0x38]; } DVDFileInfo;
typedef struct { void* messages; int capacity; } OSMessageQueue;
#define TRUE 1
#define FALSE 0
#define OS_MESSAGE_BLOCK 1
#define ALIGN_DECL(n) __attribute__((aligned(n)))
/* Retail layouts are checked by MWCC; host pointers intentionally grow. */
#define STATIC_ASSERT(...)
static void AttractMovieAudio_DmaCallback(void) {}
static void PlayControl(u32 retrace) { (void)retrace; }
'''

SERVICES = r'''
static int cases, thpResult, openResult, closes, initQueues, sentMessages;
static int irqDepth, flushes, starts, dmaInits, callbackChanges;
static int videoCreates, audioCreates, readCreates, videoStarts, audioStarts, readStarts;
static int freeReads, freeTextures, freeAudio, retraceChanges;
static void *videoInput, *audioInput;
static AIDCallback registeredAudio;
static VIRetraceCallback registeredRetrace;
static OSMessage readyValue;
static void previousAudio(void) {}
static void previousRetrace(u32 n) { (void)n; }
static int THPInit(void) { return thpResult; }
static u32 OSDisableInterrupts(void) { assert(!irqDepth); irqDepth++; return 17; }
static void OSRestoreInterrupts(u32 saved) { assert(saved == 17 && irqDepth == 1); irqDepth--; }
static AIDCallback AIRegisterDMACallback(AIDCallback cb) {
    assert(irqDepth == 1); AIDCallback old = registeredAudio;
    registeredAudio = cb; callbackChanges++; return old;
}
static void DCFlushRange(void* p, u32 n) {
    assert(p == gAttractMovieAudioDmaBuffer && n == 1280);
    for (u32 i = 0; i < n; i++) assert(((u8*)p)[i] == 0);
    flushes++;
}
static void AIInitDMA(u32 address, u32 size) {
    /* The SDK accepts a physical 32-bit DMA address; it is never dereferenced. */
    assert(address == (u32)(uintptr_t)gAttractMovieAudioDmaBuffer && size == 640); dmaInits++;
}
static void AIStartDMA(void) { starts++; }
static void OSInitMessageQueue(OSMessageQueue* q, void* messages, s32 count) {
    assert((uintptr_t)q > UINT32_MAX && (uintptr_t)messages > UINT32_MAX);
    if (q == &gAttractMovieSpentTextureSetQueue) {
        assert(messages == gAttractMovieSpentTextureSetMessages && count == 3);
    } else {
        assert(q == &gAttractMoviePrepareReadyQueue);
        assert(messages == &gAttractMoviePrepareReadyMessage && count == 1);
    }
    q->messages = messages; q->capacity = count; initQueues++;
}
static int OSSendMessage(OSMessageQueue* q, OSMessage message, s32 flags) {
    assert(q == &gAttractMoviePrepareReadyQueue && flags == OS_MESSAGE_BLOCK);
    readyValue = message; sentMessages++; return 1;
}
static int OSReceiveMessage(OSMessageQueue* q, OSMessage* message, s32 flags) {
    assert(q == &gAttractMoviePrepareReadyQueue && flags == OS_MESSAGE_BLOCK);
    assert(q->messages == &gAttractMoviePrepareReadyMessage && q->capacity == 1);
    *message = readyValue; return 1;
}
static int DVDOpen(const char* name, DVDFileInfo* file) {
    assert(!strcmp(name, "starfox.thp") && file == &gAttractMoviePlayer.fileInfo); return openResult;
}
static int DVDClose(DVDFileInfo* file) {
    assert(file == &gAttractMoviePlayer.fileInfo); closes++; return 1;
}
static struct Read {
    void* buffer; u32 length, offset; int result; unsigned char payload[64];
} reads[8];
static int readCount, readIndex;
static void addRead(void* p, u32 length, u32 offset, int result, const void* data, size_t size) {
    assert(readCount < 8 && size <= 64);
    struct Read* r = &reads[readCount++];
    *r = (struct Read){.buffer=p, .length=length, .offset=offset, .result=result};
    if (data) memcpy(r->payload, data, size);
}
static int DVDRead(DVDFileInfo* file, void* data, u32 length, u32 offset) {
    assert(file == &gAttractMoviePlayer.fileInfo && readIndex < readCount);
    struct Read* r = &reads[readIndex++];
    assert(data == r->buffer && length == r->length && offset == r->offset);
    assert((uintptr_t)data > UINT32_MAX);
    if (r->result >= 0) memcpy(data, r->payload, length < 64 ? length : 64);
    return r->result;
}
static BOOL CreateVideoDecodeThread(int priority, void* input) {
    assert(priority == 15); videoCreates++; videoInput = input; return FALSE;
}
static BOOL CreateAudioDecodeThread(int priority, void* input) {
    assert(priority == 12); audioCreates++; audioInput = input; return FALSE;
}
static BOOL CreateReadThread(int priority) { assert(priority == 8); readCreates++; return FALSE; }
static void PushFreeReadBuffer(AttractMovieReadBuffer* p) {
    assert(p == &gAttractMoviePlayer.readBuffer[freeReads++]);
}
static void PushFreeTextureSet(OSMessage p) { assert(p == &gAttractMoviePlayer.textureSet[freeTextures++]); }
static void PushFreeAudioBuffer(OSMessage p) { assert(p == &gAttractMoviePlayer.audioBuffer[freeAudio++]); }
static void VideoDecodeThreadStart(void) { assert(initQueues == 1); videoStarts++; }
static void AudioDecodeThreadStart(void) { assert(videoStarts == 1); audioStarts++; }
static void ReadThreadStart(void) { assert(videoStarts == 1); readStarts++; }
static VIRetraceCallback VISetPostRetraceCallback(VIRetraceCallback cb) {
    assert(cb == PlayControl); VIRetraceCallback old = registeredRetrace;
    registeredRetrace = cb; retraceChanges++; return old;
}
'''

CHECKS = r'''
static unsigned char movie[256];
static void reset(void) {
    memset(&gAttractMoviePlayer, 0xa5, sizeof(gAttractMoviePlayer));
    memset(gAttractMovieAudioDmaBuffer, 0x5a, sizeof(gAttractMovieAudioDmaBuffer));
    memset(gAttractMovieDvdReadBuffer, 0xcc, sizeof(gAttractMovieDvdReadBuffer));
    for (int i = 0; i < 3; i++) gAttractMovieSpentTextureSetMessages[i] = (void*)(uintptr_t)(i + 1);
    gAttractMovieAudioActive = 0;
    thpResult = openResult = 1;
    closes = initQueues = sentMessages = irqDepth = flushes = starts = dmaInits = callbackChanges = 0;
    videoCreates = audioCreates = readCreates = videoStarts = audioStarts = readStarts = 0;
    freeReads = freeTextures = freeAudio = retraceChanges = readCount = readIndex = 0;
    videoInput = audioInput = NULL;
    registeredAudio = NULL; registeredRetrace = previousRetrace; readyValue = (void*)1;
    cases++;
}
static void checkInit(void) {
    for (int mode = 0; mode <= 1; mode++) for (int prior = 0; prior <= 1; prior++) {
        reset(); registeredAudio = prior ? previousAudio : NULL;
        assert(AttractMovieAudio_Init(mode) == (!mode || prior));
        assert(initQueues == 1 && irqDepth == 0);
        for (size_t i = 0; i < sizeof(gAttractMoviePlayer); i++) assert(((u8*)&gAttractMoviePlayer)[i] == 0);
        for (int i = 0; i < 3; i++) assert(gAttractMovieSpentTextureSetMessages[i] == (void*)(uintptr_t)(i+1));
        for (int i = 0; i < 16; i++) assert(gAttractMovieDvdReadBuffer[i] == 0xcccccccc);
        assert(flushes == !mode && starts == !mode && dmaInits == !mode);
        if (!mode || prior) {
            assert(gAttractMovieAudioActive && registeredAudio == AttractMovieAudio_DmaCallback);
            AttractMovieAudio_Shutdown(); assert(!gAttractMovieAudioActive);
            assert(registeredAudio == (prior ? previousAudio : AttractMovieAudio_DmaCallback));
        } else assert(!gAttractMovieAudioActive && !registeredAudio && callbackChanges == 2);
    }
    reset(); thpResult = 0; assert(!AttractMovieAudio_Init(0));
    assert(initQueues == 1 && !callbackChanges && !starts && !gAttractMovieAudioActive);
}
static THPHeader header;
static THPFrameCompInfo components;
static AttractMovieVideoInfo video = {320, 240};
static AttractMovieAudioInfo audio = {2, 32000, 160};
static void planOpen(int hasAudio) {
    memset(&gAttractMoviePlayer, 0, sizeof(gAttractMoviePlayer));
    gAttractMovieAudioActive = 1;
    header = (THPHeader){.mMagic="THP", .mVersion=0x10000, .mNumFrames=4,
        .mCompInfoDataOffsets=64, .mOffsetDataOffsets=128, .mMovieDataOffsets=256,
        .mMovieDataSize=256, .mFirstFrameSize=32};
    components = (THPFrameCompInfo){.mNumComponents=hasAudio ? 2 : 1, .mFrameComp={0,1}};
    addRead(gAttractMovieDvdReadBuffer, 64, 0, 64, &header, sizeof(header));
    addRead(gAttractMovieDvdReadBuffer, 32, 64, 32, &components, sizeof(components));
    addRead(gAttractMovieDvdReadBuffer, 32, 84, 32, &video, sizeof(video));
    if (hasAudio) addRead(gAttractMovieDvdReadBuffer, 32, 92, 32, &audio, sizeof(audio));
}
static void checkOpen(void) {
    for (int memory = 0; memory <= 1; memory++) for (int hasAudio = 0; hasAudio <= 1; hasAudio++) {
        reset(); planOpen(hasAudio);
        assert(movieLoad("starfox.thp", memory));
        assert(readIndex == readCount && !closes && gAttractMoviePlayer.isOpen == 1);
        assert(gAttractMoviePlayer.isOnMemory == memory && gAttractMoviePlayer.audioExists == hasAudio);
        assert(!memcmp(&header, &gAttractMoviePlayer.header, sizeof(header)));
        assert(!memcmp(&video, &gAttractMoviePlayer.videoInfo, sizeof(video)));
        if (hasAudio) assert(!memcmp(&audio, &gAttractMoviePlayer.audioInfo, sizeof(audio)));
        assert(gAttractMoviePlayer.curVolume == 127 && gAttractMoviePlayer.targetVolume == 127);
        assert(!movieLoad("starfox.thp", memory));
        assert(AttractMovie_CloseFile() && closes == 1 && !gAttractMoviePlayer.isOpen);
        assert(!AttractMovie_CloseFile() && closes == 1);
    }
    for (int failure = 0; failure < 8; failure++) {
        reset(); planOpen(1);
        if (failure < 4) reads[failure].result = -1;
        if (failure == 4) reads[0].payload[0] = 'X';
        if (failure == 5) ((THPHeader*)reads[0].payload)->mVersion = 0x11000;
        if (failure == 6) ((THPFrameCompInfo*)reads[1].payload)->mFrameComp[0] = 9;
        if (failure == 7) openResult = 0;
        assert(!movieLoad("starfox.thp", 0) && !gAttractMoviePlayer.isOpen);
        /* Retail leaves the DVD open for an unknown component type. */
        assert(closes == (failure < 6));
    }
    reset(); memset(&gAttractMoviePlayer, 0, sizeof(gAttractMoviePlayer));
    assert(!movieLoad("starfox.thp", 0) && !readIndex);
}
static void setupPrepare(int memory, int hasAudio) {
    reset(); memset(&gAttractMoviePlayer, 0, sizeof(gAttractMoviePlayer));
    gAttractMoviePlayer.isOpen = 1; gAttractMoviePlayer.header = header;
    gAttractMoviePlayer.isOnMemory = memory; gAttractMoviePlayer.audioExists = hasAudio;
    gAttractMoviePlayer.movieData = movie; gAttractMovieLoopCompleted = 1;
}
static void checkPrepare(void) {
    for (int memory = 0; memory <= 1; memory++) for (int hasAudio = 0; hasAudio <= 1; hasAudio++)
    for (int frame = 0; frame <= 2; frame += 2) for (int ready = 0; ready <= 1; ready++) {
        setupPrepare(memory, hasAudio);
        u32 offsets[] = {64, 112};
        if (frame) addRead(gAttractMovieDvdReadBuffer, 32, 132, 32, offsets, sizeof(offsets));
        if (memory) addRead(movie, 256, 256, 256, NULL, 0);
        readyValue = (OSMessage)(ptrdiff_t)ready;
        assert(prepareAttractMode(frame, 0x105) == ready);
        assert(!gAttractMovieLoopCompleted && readIndex == readCount);
        assert(gAttractMoviePlayer.initOffset == 256 + (frame ? 64 : 0));
        assert(gAttractMoviePlayer.initReadSize == (frame ? 48 : 32));
        assert(gAttractMoviePlayer.initReadFrame == frame && gAttractMoviePlayer.playFlags == 5);
        assert(videoCreates == 1 && audioCreates == hasAudio && readCreates == !memory);
        assert(videoStarts == 1 && audioStarts == hasAudio && readStarts == !memory);
        assert(videoInput == (memory ? movie + (frame ? 64 : 0) : NULL));
        if (hasAudio) assert(audioInput == videoInput);
        assert(freeReads == (memory ? 0 : 10) && freeTextures == 3 && freeAudio == (hasAudio ? 3 : 0));
        assert(gAttractMoviePlayer.state == ready && retraceChanges == ready);
        if (ready) {
            assert(OldVIPostCallback == previousRetrace && !gAttractMoviePlayer.curTextureSet);
            assert(!gAttractMoviePlayer.curAudioBuffer && !gAttractMoviePlayer.curVideoFrameNumber);
            assert(!gAttractMoviePlayer.curAudioFrameNumber);
        }
    }
    for (int failure = 0; failure < 6; failure++) {
        setupPrepare(1, 1);
        if (failure == 0) gAttractMoviePlayer.isOpen = 0;
        if (failure == 1) gAttractMoviePlayer.state = 1;
        if (failure == 2) gAttractMoviePlayer.header.mOffsetDataOffsets = 0;
        if (failure == 3) gAttractMoviePlayer.header.mNumFrames = 2;
        if (failure == 4) addRead(gAttractMovieDvdReadBuffer, 32, 132, -1, NULL, 0);
        if (failure == 5) addRead(movie, 256, 256, -1, NULL, 0);
        assert(!prepareAttractMode(failure == 5 ? 0 : 2, 1));
        assert(!videoCreates && !audioCreates && !readCreates && !retraceChanges);
    }
    reset();
    PrepareReady(0); assert(!readyValue);
    PrepareReady(1); assert(readyValue == (OSMessage)1);
    PrepareReady(-1); assert((ptrdiff_t)readyValue == -1 && sentMessages == 3);
}
int main(void) {
    assert(sizeof(void*) == 8 && (uintptr_t)&gAttractMoviePlayer > UINT32_MAX);
    assert((uintptr_t)movie > UINT32_MAX && (uintptr_t)gAttractMovieDvdReadBuffer % 32 == 0);
    checkInit(); checkOpen(); checkPrepare();
    printf("%d THP lifecycle scenarios passed with native pointers\n", cases);
}
'''


def declarations(path):
    text = (ROOT / path).read_text()
    text = re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)
    return text


def harness():
    source = (ROOT / 'src/main/thp/THPPlayer.c').read_text()
    records = '\n'.join(declarations(path) for path in [
        'include/dolphin/thp/THPFile.h', 'include/dolphin/thp/THPInfo.h',
        'include/main/dll/FRONT/attract_movie.h'])
    storage = source[source.index('u8 gAttractMovieLoopCompleted;'):source.index('static void AttractMovieAudio_Mix')]
    functions = []
    for name in ['AttractMovieAudio_Init', 'AttractMovieAudio_Shutdown', 'movieLoad',
                 'AttractMovie_CloseFile', 'InitAllMessageQueue', 'PrepareReady', 'prepareAttractMode']:
        start, end = find_function_body(source, name)
        line = source.rfind('\n', 0, source.rfind(name, 0, start)) + 1
        functions.append(source[line:end + 1])
    return '\n'.join([PRELUDE, records, storage, SERVICES, *functions, CHECKS])


class THPPlayerNativeTest(unittest.TestCase):
    def test_lifecycle(self):
        compiler = shutil.which('clang') or shutil.which('cc')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='thp-player-') as directory:
            path = Path(directory)
            source = path / 'player.c'
            source.write_text(harness())
            for optimization in ['-O0', '-O2']:
                with self.subTest(optimization=optimization):
                    exe = path / 'player'
                    subprocess.run([compiler, '-std=c11', optimization, '-g', '-Wall', '-Wextra',
                                    '-Werror', '-Wno-pointer-to-int-cast',
                                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                                    str(source), '-o', str(exe)], check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
