#!/usr/bin/env python3
"""Exercise the complete DVD audio stream TU with independent native SDK objects."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;
typedef float f32;
typedef struct DVDCommandBlock { void* links[3]; u8 opaque[27]; } DVDCommandBlock;
typedef struct DVDFileInfo { void* links[2]; DVDCommandBlock block; u8 opaque[33]; } DVDFileInfo;
#define AI_STREAM_START 1
#define AI_STREAM_STOP 0
static void AISetStreamVolLeft(u8);
static void AISetStreamVolRight(u8);
static void AISetStreamPlayState(u32);
static int DVDCancelStreamAsync(DVDCommandBlock*, void (*)(s32,DVDCommandBlock*));
static int DVDOpen(const char*,DVDFileInfo*);
static int DVDPrepareStreamAsync(DVDFileInfo*,u32,u32,void (*)(s32,DVDFileInfo*));
static int DVDStopStreamAtEndAsync(DVDCommandBlock*,void (*)(s32,DVDCommandBlock*));
static void OSReport(const char*,...);
static int getGameState(void);
static void Music_Trigger(u16,int);
static u32 audioIsChannelUnavailable(u32);
static int concatThreeStrings(char*,void*,const char*,const char*,const char*);
static void Sfx_StopAllObjectSounds(void);
static void padUpdate(void);
static void checkReset(void);
static void mmFreeTick(int);
static void waitNextFrame(void);
static void dvdCheckError(void);
static void gameTextRun(void);
static void GXFlush_(int,int);
u32 gAudioActiveChannelMask, gAudioStreamPlayAddrCallbackResult;
u8 gDvdErrorPauseActive;
f32 timeDelta;
'''
SERVICES = r'''
static int cases, leftCalls, rightCalls, playCalls, lastPlay, warnings, stoppedObjects;
static int opens, prepares, stopEnds, cancelledCurrent, cancelledPrepared, joins, musicCalls;
static int padCalls, resets, dvdChecks, preparedNotifications;
static int openResult, concatResult, cancelMode, channelBlocked, finishCancelAt, expectedSlot;
static int gameStates[4], gameStateIndex, gameStateCount;
static u8 leftVolume, rightVolume;
static StreamEntry entries[3];
static void (*pendingPrepare)(s32,DVDFileInfo*);
static void (*pendingCancel)(s32,DVDCommandBlock*);
static void AISetStreamVolLeft(u8 value) { leftCalls++; leftVolume = value; }
static void AISetStreamVolRight(u8 value) { rightCalls++; rightVolume = value; }
static void AISetStreamPlayState(u32 value) { playCalls++; lastPlay = value; }
static int getGameState(void) {
    int i = gameStateIndex++;
    return gameStates[i < gameStateCount ? i : gameStateCount-1];
}
static int DVDCancelStreamAsync(DVDCommandBlock* block, void (*callback)(s32,DVDCommandBlock*)) {
    if (block == &gAudioStreamPreparedCommand) {
        assert(callback == AudioStream_CancelPreparedCallback); cancelledPrepared++;
    } else {
        assert(block == &gAudioStreamDvdBlockCurrent && callback == AudioStream_CancelCallback);
        cancelledCurrent++;
    }
    if (!cancelMode) return 0;
    if (cancelMode == 1) callback(0,block);
    else pendingCancel = callback;
    return 1;
}
static int DVDOpen(const char* path, DVDFileInfo* file) {
    assert(file == &gAudioStreamFile && (uintptr_t)file > UINT32_MAX);
    char expected[64]; snprintf(expected,sizeof(expected),"/streams/%s.adp",entries[expectedSlot].name);
    assert(strcmp(path,expected) == 0); opens++; return openResult;
}
static int DVDPrepareStreamAsync(DVDFileInfo* file, u32 length, u32 offset,
                                  void (*callback)(s32,DVDFileInfo*)) {
    assert(file == &gAudioStreamFile && !length && !offset && callback == AudioStream_PrepareCallback);
    assert(gAudioStreamPreparingId == expectedSlot+1 && gAudioStreamDvdState == 1);
    pendingPrepare = callback; prepares++; return 0; /* Retail ignores this return. */
}
static int DVDStopStreamAtEndAsync(DVDCommandBlock* block, void (*callback)(s32,DVDCommandBlock*)) {
    assert(block == &gAudioStreamStopAtEndCommand && callback == NULL && prepares == stopEnds+1);
    stopEnds++; return 0;
}
static void OSReport(const char* format,...) {
    assert(strcmp(format,"WARNING:DVDCancelStreamAsync returned FALSE\n") == 0); warnings++;
}
static void Music_Trigger(u16 id, int mode) {
    assert(id == (musicCalls ? 244 : 168) && mode == musicCalls); musicCalls++;
}
static u32 audioIsChannelUnavailable(u32 mask) { assert(mask == 8); return channelBlocked; }
static int concatThreeStrings(char* path, void* capacity, const char* directory,
                               const char* name, const char* extension) {
    assert((uintptr_t)capacity == 64 && strcmp(directory,"/streams/") == 0);
    assert(name == entries[expectedSlot].name && strcmp(extension,".adp") == 0);
    snprintf(path,64,"%s%s%s",directory,name,extension); joins++; return concatResult;
}
static void Sfx_StopAllObjectSounds(void) { stoppedObjects++; }
static void padUpdate(void) {
    padCalls++;
    if (pendingCancel && padCalls == finishCancelAt) {
        void (*callback)(s32,DVDCommandBlock*) = pendingCancel; pendingCancel = NULL;
        callback(0,&gAudioStreamDvdBlockCurrent);
    }
    assert(padCalls < 10);
}
static void checkReset(void) { resets++; }
static void dvdCheckError(void) { dvdChecks++; }
static void mmFreeTick(int ignored) { (void)ignored; assert(0); }
static void waitNextFrame(void) { assert(0); }
static void gameTextRun(void) { assert(0); }
static void GXFlush_(int a,int b) { (void)a; (void)b; assert(0); }
static void notified(void) { preparedNotifications++; }
'''
CHECKS = r'''
static void reset(void) {
    memset(entries,0,sizeof(entries));
    for (int i = 0; i < 3; i++) {
        entries[i].id = i == 2 ? 1318 : 100+i;
        snprintf(entries[i].name,sizeof(entries[i].name),"sample%d",i);
        entries[i].fadeModeA = i; entries[i].fadeModeB = 2-i;
        entries[i].volume = i == 1 ? 127 : 31; entries[i].lengthRaw = i == 1 ? 0 : 1500;
        entries[i].stopObjectSounds = i == 2; entries[i].fullVolume = i == 1;
    }
    gStreamsData = entries; gStreamsCount = 3;
    gAudioStreamPlaying = gAudioStreamDvdState = 0;
    gAudioStreamPreparedId = gAudioStreamPreparingId = gAudioStreamCurrentId = gAudioStreamStartWhenPrepared = 0;
    gAudioStreamPreparedCallback = NULL; gAudioStreamDefaultVolume = 127;
    gAudioStreamMusicFadeFlagA = gAudioStreamMusicFadeFlagB = gAudioActiveChannelMask = 0;
    gAudioStreamPos = gAudioStreamEndPos = 0; gDvdErrorPauseActive = 0;
    leftCalls = rightCalls = playCalls = warnings = stoppedObjects = 0;
    opens = prepares = stopEnds = cancelledCurrent = cancelledPrepared = joins = musicCalls = 0;
    padCalls = resets = dvdChecks = preparedNotifications = 0;
    pendingPrepare = NULL; pendingCancel = NULL; openResult = concatResult = 1;
    cancelMode = 1; channelBlocked = 0; finishCancelAt = 3; expectedSlot = 0;
    gameStates[0] = 1; gameStateCount = 1; gameStateIndex = 0;
    lastPlay = -1; leftVolume = rightVolume = 99; cases++;
}
static void cleared(void) {
    assert(!gAudioStreamPreparedId && !gAudioStreamPreparingId && !gAudioStreamCurrentId);
    assert(!gAudioStreamStartWhenPrepared && !gAudioActiveChannelMask);
    assert(!gAudioStreamMusicFadeFlagA && !gAudioStreamMusicFadeFlagB);
}
static void playLookup(void) {
    const int rejected[] = {1228,999};
    for (int i = 0; i < 2; i++) {
        reset(); assert(!AudioStream_Play(rejected[i],notified)); assert(!joins && !opens && !prepares);
    }
    reset(); channelBlocked = 1; assert(!AudioStream_Play(1318,notified)); assert(musicCalls == 2 && !joins);
    reset(); gStreamsCount = 0; assert(!AudioStream_Play(100,notified) && !joins);
    reset(); gAudioStreamDvdState = 1; assert(!AudioStream_Play(100,notified) && !joins);
    reset(); concatResult = 0; assert(!AudioStream_Play(100,notified) && joins == 1 && !opens);
    reset(); openResult = 0; assert(!AudioStream_Play(100,notified) && opens == 1 && !prepares);
    for (int slot = 0; slot < 3; slot++) for (int mode = 0; mode < 4; mode++) {
        reset(); expectedSlot = slot; cancelMode = mode == 3 ? 2 : mode;
        gAudioStreamCurrentId = 7; gAudioStreamPlaying = 1;
        if (mode == 3) gDvdErrorPauseActive = 1;
        gAudioStreamDefaultVolume = mode ? 255 : 0;
        assert(AudioStream_Play(entries[slot].id,notified) == 1);
        assert(opens == 1 && prepares == 1 && stopEnds == 1 && cancelledCurrent == 1);
        assert(cancelledPrepared == 0 && warnings == !cancelMode);
        assert(gAudioStreamEndPos == (slot == 1 ? 9.0e9f : 15.0f));
        assert(gAudioStreamMusicFadeFlagA == (slot != 0) && gAudioStreamMusicFadeFlagB == (slot != 2));
        assert(stoppedObjects == (slot == 2));
        assert(gAudioActiveChannelMask == (mode == 2 ? 0 : slot == 1 ? 4 : 0));
        int waits = mode == 2 ? 3 : mode == 3 ? 1 : 0;
        assert(padCalls == waits && resets == waits && dvdChecks == waits);
        u8 volume = ((entries[slot].volume+1)*gAudioStreamDefaultVolume)>>7;
        assert(leftVolume == volume && rightVolume == volume);
        assert(gAudioStreamPreparingId == slot+1 && gAudioStreamDvdState == 1);
        assert(gAudioStreamPreparedCallback == notified && !gAudioStreamPlaying);
        AudioStream_StartPrepared(); assert(gAudioStreamStartWhenPrepared == 1);
        pendingPrepare(-1,&gAudioStreamFile); /* Retail does not inspect the prepare result. */
        assert(gAudioStreamCurrentId == slot+1 && gAudioStreamPlaying && !gAudioStreamDvdState);
        assert(!gAudioStreamPreparingId && !gAudioStreamPreparedId && !gAudioStreamStartWhenPrepared);
        assert(lastPlay == 1 && !preparedNotifications);
    }
    reset(); assert(AudioStream_Play(100,notified)); pendingPrepare(0,&gAudioStreamFile);
    assert(preparedNotifications == 1 && gAudioStreamPreparedId == 1 && !gAudioStreamCurrentId);
    AudioStream_StartPrepared(); assert(gAudioStreamCurrentId == 1 && gAudioStreamPlaying);
}
static void cancellation(void) {
    for (int all = 0; all < 2; all++) for (int preparing = 0; preparing < 2; preparing++) {
        for (int current = 0; current < 2; current++) for (int success = 0; success < 2; success++) {
            reset(); cancelMode = success;
            gAudioStreamDvdState = preparing; gAudioStreamCurrentId = current ? 3 : 0;
            gAudioStreamPlaying = 1;
            if (all) AudioStream_StopAll(); else AudioStream_StopCurrent();
            assert(cancelledPrepared == (all && preparing));
            assert(cancelledCurrent == (current && !(all && preparing)));
            assert(warnings == ((!success) * (cancelledPrepared+cancelledCurrent)));
            assert(!gAudioStreamPlaying); cleared();
        }
    }
    for (int success = 0; success < 2; success++) {
        reset(); cancelMode = success; gAudioStreamDvdState = 1; gAudioStreamPlaying = 1;
        gAudioStreamCurrentId = gAudioStreamPreparingId = gAudioStreamPreparedId = 4;
        gAudioStreamStartWhenPrepared = gAudioActiveChannelMask = 1;
        AudioStream_CancelPrepared(); cleared();
        assert(cancelledPrepared == 1 && gAudioStreamDvdState == !success && gAudioStreamPlaying == 1);
    }
    for (int result = -1; result <= 1; result++) {
        reset(); gAudioStreamPlaying = 1; gAudioActiveChannelMask = 4;
        AudioStream_CancelCallback(result,&gAudioStreamDvdBlockCurrent);
        assert(playCalls == (result == 0) && !gAudioStreamPlaying && !gAudioActiveChannelMask);
        gAudioStreamDvdState = 1; AudioStream_CancelPreparedCallback(result,&gAudioStreamPreparedCommand);
        assert(!gAudioStreamDvdState);
    }
}
static void callbacksAndVolumes(void) {
    reset(); gAudioStreamPreparingId = 5; gAudioStreamDvdState = 1; gameStates[0] = 0;
    AudioStream_PrepareCallback(0,&gAudioStreamFile);
    assert(gAudioStreamPreparingId == 5 && !gAudioStreamPreparedId && !gAudioStreamDvdState);
    for (int throughCallback = 0; throughCallback < 2; throughCallback++) {
        reset(); gameStates[0] = 1; gameStates[1] = 0; gameStateCount = 2;
        gAudioStreamPlaying = 1;
        if (throughCallback) {
            gAudioStreamPreparingId = 8; gAudioStreamStartWhenPrepared = 1;
            AudioStream_PrepareCallback(0,&gAudioStreamFile);
        } else { gAudioStreamPreparedId = 8; AudioStream_StartPrepared(); }
        assert(!gAudioStreamPlaying && !playCalls && gAudioStreamPreparedId == 8);
    }
    reset(); gameStates[0] = 0; gAudioStreamPreparedId = 8; AudioStream_StartPrepared();
    assert(gAudioStreamPreparedId == 8 && !playCalls);
    reset(); gAudioStreamMusicFadeFlagA = gAudioStreamMusicFadeFlagB = gAudioActiveChannelMask = 1;
    AudioStream_StartPrepared(); cleared();
    const u32 results[] = {0,0x100,1,0xffffffff};
    for (int current = 0; current < 2; current++) for (int i = 0; i < 4; i++) {
        reset(); gAudioStreamPlaying = 1; gAudioStreamCurrentId = current ? 7 : 0;
        gAudioStreamPlayAddrCallbackDone = 0; AudioStream_PlayAddrCallback(results[i]);
        assert(gAudioStreamPlayAddrCallbackResult == results[i] && gAudioStreamPlayAddrCallbackDone == 1);
        assert(gAudioStreamPlaying == ((results[i]&255) != 0));
        assert(playCalls == (current && !(results[i]&255)));
    }
    const int volumes[] = {0,1,127,128,255};
    for (int i = 0; i < 5; i++) {
        reset(); AudioStream_SetVolume(volumes[i]); AudioStream_SetDefaultVolume(volumes[i]);
        assert(leftVolume == volumes[i] && rightVolume == volumes[i] && gAudioStreamDefaultVolume == volumes[i]);
        assert(gAudioStreamVolumeLeft == volumes[i] && gAudioStreamVolumeRight == volumes[i]);
    }
    reset(); gAudioStreamCurrentId = 1; gAudioStreamPos = 2; gAudioStreamEndPos = 2;
    gAudioStreamMusicFadeFlagA = 4; gAudioStreamMusicFadeFlagB = 2;
    assert(AudioStream_GetCurrentId() == 1 && AudioStream_GetMusicFadeFlagA() == 4 && AudioStream_GetMusicFadeFlagB() == 2);
    timeDelta = 30; AudioStream_UpdateFadeTimer(); assert(gAudioStreamPos == 2.5f);
    assert(!AudioStream_GetMusicFadeFlagA() && !AudioStream_GetMusicFadeFlagB());
    gAudioStreamCurrentId = 0; AudioStream_UpdateFadeTimer(); assert(gAudioStreamPos == 0);
    gAudioStreamDvdState = 255; assert(AudioStream_IsPreparing() == 255); AudioStream_Nop(77);
    AudioStream_Init(); assert(leftVolume == 0 && rightVolume == 0 && gAudioStreamDefaultVolume == 127);
    assert(!gAudioStreamCurrentId && !gAudioStreamMusicFadeFlagA && !gAudioStreamMusicFadeFlagB);
}
int main(void) {
    assert(sizeof(void*) == 8 && (uintptr_t)entries > UINT32_MAX);
    playLookup(); cancellation(); callbacksAndVolumes();
    printf("%d complete-TU DVD stream scenarios passed with native pointers\n",cases);
}
'''


def without_includes(path):
    return re.sub(r'^#include[^\n]*\n', '', (ROOT / path).read_text(), flags=re.M)


def harness():
    internal = (ROOT / 'include/main/audio_internal.h').read_text()
    record = re.search(r'typedef struct StreamEntry \{.*?\} StreamEntry;', internal, re.S)[0]
    ids = without_includes('include/main/audio/music_trigger_ids.h')
    return '\n'.join([PRELUDE, record, ids, without_includes('include/main/audio/stream_api.h'),
                      without_includes('src/main/audio_stream.c'), SERVICES, CHECKS])


class AudioStreamNativeTest(unittest.TestCase):
    def test_complete_tu(self):
        compiler = shutil.which('clang') or shutil.which('cc')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='audio-stream-') as directory:
            path = Path(directory)
            source = path / 'stream.c'
            source.write_text(harness())
            for optimization in ['-O0', '-O2']:
                with self.subTest(optimization=optimization):
                    exe = path / 'stream'
                    subprocess.run([compiler, '-std=c11', optimization, '-g', '-Wall', '-Wextra',
                                    '-Werror', '-Wno-unused-parameter', '-Wno-deprecated-non-prototype',
                                    '-fsanitize=address,undefined', '-fno-common', '-fno-omit-frame-pointer',
                                    str(source), '-o', str(exe)], check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
