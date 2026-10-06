/* DVD audio streaming and its playback state. */
#include "main/audio/stream_api.h"
#include "main/audio/sfx.h"
#include "main/audio_internal.h"
#include "main/fileio.h"
#include "main/frame_timing.h"
#include "main/textrender_api.h"
#include "main/gameloop_api.h"
#include "main/mm.h"
#include "main/objseq_api.h"
#include "main/pad.h"
#include "main/pi_dolphin_api.h"
#include "main/resource.h"
#include "main/vecmath.h"
#define SYNTH_INTERNAL_USE_PROJECT_TYPES
#include "src/musyx/runtime/synth_internal.h"
#include "game/objects/object.h"
#include "main/audio/music_trigger_ids.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/string.h"
#include "dolphin/ai.h"
#include "dolphin/dvd.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/os/OSRtc.h"
#include "main/audio/music_api.h"
#include "main/pi_flush_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"

static const f32 gAudioStreamEndPosInfinite = 9.0e9f;
static const f32 gAudioStreamFramesPerSecond = 60.0f;

u8 gAudioStreamVolumeLeft = 0xFF;
u8 gAudioStreamVolumeRight = 0xFF;
u8 gAudioStreamPlayAddrCallbackDone = 1;
u8 gAudioStreamDefaultVolume = 0x7F;
char sAdpExtension[] = ".adp";

s32 gAudioStreamPreparedId;
s32 gAudioStreamPreparingId;
s32 gAudioStreamStartWhenPrepared;
s32 gAudioStreamCurrentId;
void (*gAudioStreamPreparedCallback)(void);
u32 gAudioStreamMusicFadeFlagA;
u32 gAudioStreamMusicFadeFlagB;
f32 gAudioStreamPos;
int gStreamsCount;
StreamEntry* gStreamsData;
f32 gAudioStreamEndPos;
u8 gAudioStreamDvdState;
u8 gAudioStreamPlaying;

static void AudioStream_CancelCallback(s32 result, DVDCommandBlock* block);
static void AudioStream_CancelPreparedCallback(s32 result, DVDCommandBlock* block);
static void AudioStream_PrepareCallback(s32 result, DVDFileInfo* fileInfo);

int gAudioStreamFadeTable[] = {0, 2, 4};
char sDvdCancelStreamWarning[0x30] = "WARNING:DVDCancelStreamAsync returned FALSE\n";
char sAudioStreamDirectory[0xC] = "/streams/";

DVDFileInfo gAudioStreamFile;
DVDCommandBlock gAudioStreamStopAtEndCommand;
DVDCommandBlock gAudioStreamPreparedCommand;
DVDCommandBlock gAudioStreamDvdBlockCurrent;

void AudioStream_PlayAddrCallback(u32 result)
{
    if ((result & 0xff) == 0)
    {
        gAudioStreamPlaying = 0;
        if (gAudioStreamCurrentId != 0)
        {
            AISetStreamVolLeft(0);
            AISetStreamVolRight(0);
            gAudioStreamCurrentId = 0;
            gAudioActiveChannelMask = 0;
            AISetStreamPlayState(AI_STREAM_STOP);
            gAudioStreamMusicFadeFlagB = 0;
            gAudioStreamMusicFadeFlagA = 0;
        }
    }
    gAudioStreamPlayAddrCallbackResult = result;
    gAudioStreamPlayAddrCallbackDone = 1;
}

static void AudioStream_PrepareCallback(s32 result, DVDFileInfo* fileInfo) {
    (void)result;
    (void)fileInfo;
    if (getGameState() != 1) {
        gAudioStreamDvdState = 0;
        return;
    }
    gAudioStreamPreparedId = gAudioStreamPreparingId;
    gAudioStreamPreparingId = 0;
    if (gAudioStreamStartWhenPrepared != 0) {
        if (getGameState() == 1) {
            AISetStreamVolLeft(gAudioStreamVolumeLeft);
            AISetStreamVolRight(gAudioStreamVolumeRight);
            AISetStreamPlayState(AI_STREAM_START);
            gAudioStreamPlaying = 1;
            gAudioStreamPos = 0.0f;
            gAudioStreamCurrentId = gAudioStreamPreparedId;
            gAudioStreamPreparedId = 0;
            gAudioStreamPreparingId = 0;
            gAudioStreamStartWhenPrepared = 0;
        } else {
            gAudioStreamPlaying = 0;
        }
    } else if (gAudioStreamPreparedCallback != NULL) {
        gAudioStreamPreparedCallback();
    }
    gAudioStreamDvdState = 0;
}

void AudioStream_Init(void)
{
    AISetStreamVolLeft(0);
    AISetStreamVolRight(0);
    gAudioStreamCurrentId = 0;
    gAudioStreamMusicFadeFlagA = 0;
    gAudioStreamMusicFadeFlagB = 0;
    gAudioStreamDefaultVolume = 0x7f;
    gAudioStreamStartWhenPrepared = 0;
}

void AudioStream_SetDefaultVolume(volume)
u8 volume;
{
    gAudioStreamDefaultVolume = volume;
}

void AudioStream_UpdateFadeTimer(void)
{
    if (gAudioStreamCurrentId != 0)
    {
        f32 position = gAudioStreamPos;
        gAudioStreamPos = position + (timeDelta / gAudioStreamFramesPerSecond);
    }
    else
    {
        gAudioStreamPos = 0.0f;
    }
}

int AudioStream_Play(int id, void (*preparedCallback)(void))
{
    char path[64];
    u8 vol;
    int* fadeTable;
    StreamEntry* s;
    int count;
    int slot;
    int i;
    u8 stopped;

    fadeTable = gAudioStreamFadeTable;
    s = gStreamsData;
    count = gStreamsCount;
    slot = -1;

    if (id == 1228)
    {
        return 0;
    }
    if (id == 1318)
    {
        Music_Trigger(MUSICTRIG_drako_3, 0);
        Music_Trigger(MUSICTRIG_TTH_Night, 1);
    }
    if ((int)audioIsChannelUnavailable(8) != 0)
    {
        return 0;
    }

    for (i = count; i != 0; i--)
    {
        if (s->id == id)
        {
            slot = (s - gStreamsData) + 1;
            break;
        }
        s++;
    }

    if (slot == -1)
    {
        return 0;
    }
    if (gAudioStreamDvdState != 0)
    {
        return 0;
    }
    gAudioStreamDvdState = 0;

    if (concatThreeStrings(path, (void*)0x40, sAudioStreamDirectory, s->name, sAdpExtension) != 0)
    {
        if (DVDOpen(path, &gAudioStreamFile) == 0)
        {
            return 0;
        }

        if (gAudioStreamCurrentId != 0)
        {
            AISetStreamVolLeft(0);
            AISetStreamVolRight(0);
            if (DVDCancelStreamAsync(&gAudioStreamDvdBlockCurrent, AudioStream_CancelCallback) == 0)
            {
                OSReport(sDvdCancelStreamWarning);
                gAudioStreamPlaying = 0;
            }
            gAudioStreamPreparedId = 0;
            gAudioStreamPreparingId = 0;
            gAudioStreamCurrentId = 0;
            gAudioStreamStartWhenPrepared = 0;
            gAudioActiveChannelMask = 0;
            gAudioStreamMusicFadeFlagB = 0;
            gAudioStreamMusicFadeFlagA = 0;
        }
        else
        {
            gAudioStreamPlaying = 0;
        }

        gAudioStreamEndPos = (f32)(u32)s->lengthRaw / 100.0f;
        if (gAudioStreamEndPos == 0.0f)
        {
            gAudioStreamEndPos = gAudioStreamEndPosInfinite;
        }

        gAudioStreamMusicFadeFlagA = fadeTable[s->fadeModeA] == 0 ? 0 : 1;
        gAudioStreamMusicFadeFlagB = fadeTable[s->fadeModeB] == 0 ? 0 : 1;
        if (s->stopObjectSounds)
        {
            Sfx_StopAllObjectSounds();
        }
        gAudioActiveChannelMask = s->fullVolume ? 4 : 0;

        stopped = 0;
        while (gAudioStreamPlaying != 0)
        {
            padUpdate();
            checkReset();
            if (stopped)
            {
                mmFreeTick(0);
                waitNextFrame();
            }
            dvdCheckError();
            if (stopped)
            {
                gameTextRun();
                GXFlush_(1, 0);
            }
            if (gDvdErrorPauseActive != 0)
            {
                stopped = 1;
                gAudioStreamPlaying = 0;
            }
        }

        vol = ((s->volume + 1) * gAudioStreamDefaultVolume) >> 7;
        gAudioStreamVolumeLeft = vol;
        gAudioStreamVolumeRight = vol;
        AISetStreamVolLeft(vol);
        AISetStreamVolRight(vol);
        gAudioStreamPreparedCallback = preparedCallback;
        gAudioStreamPreparingId = slot;
        gAudioStreamDvdState = 1;
        DVDPrepareStreamAsync(&gAudioStreamFile, 0, 0, AudioStream_PrepareCallback);
        DVDStopStreamAtEndAsync(&gAudioStreamStopAtEndCommand, NULL);
        return 1;
    }
    return 0;
}

void AudioStream_StartPrepared(void)
{
    if (gAudioStreamPreparingId != 0)
    {
        gAudioStreamStartWhenPrepared = 1;
    }
    else if (gAudioStreamPreparedId != 0)
    {
        if (getGameState() == 1)
        {
            if (getGameState() == 1)
            {
                AISetStreamVolLeft(gAudioStreamVolumeLeft);
                AISetStreamVolRight(gAudioStreamVolumeRight);
                AISetStreamPlayState(AI_STREAM_START);
                gAudioStreamPlaying = 1;
                gAudioStreamPos = 0.0f;
                gAudioStreamCurrentId = gAudioStreamPreparedId;
                gAudioStreamPreparedId = 0;
                gAudioStreamPreparingId = 0;
                gAudioStreamStartWhenPrepared = 0;
            }
            else
            {
                gAudioStreamPlaying = 0;
            }
        }
    }
    else if (gAudioStreamCurrentId == 0)
    {
        gAudioStreamMusicFadeFlagB = 0;
        gAudioStreamMusicFadeFlagA = 0;
        gAudioStreamStartWhenPrepared = 0;
        gAudioActiveChannelMask = 0;
    }
}

void AudioStream_CancelPrepared(void)
{
    AISetStreamVolLeft(0);
    AISetStreamVolRight(0);
    if (DVDCancelStreamAsync(&gAudioStreamPreparedCommand,
                             AudioStream_CancelPreparedCallback) == 0)
    {
        OSReport(sDvdCancelStreamWarning);
    }
    gAudioStreamPreparedId = 0;
    gAudioStreamPreparingId = 0;
    gAudioStreamCurrentId = 0;
    gAudioStreamStartWhenPrepared = 0;
    gAudioActiveChannelMask = 0;
    gAudioStreamMusicFadeFlagB = 0;
    gAudioStreamMusicFadeFlagA = 0;
}

static void AudioStream_CancelPreparedCallback(s32 result, DVDCommandBlock* block)
{
    (void)result;
    (void)block;
    gAudioStreamDvdState = 0;
}

void AudioStream_StopCurrent(void)
{
    if (gAudioStreamCurrentId != 0)
    {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(&gAudioStreamDvdBlockCurrent, AudioStream_CancelCallback) == 0)
        {
            OSReport(sDvdCancelStreamWarning);
            gAudioStreamPlaying = 0;
        }
        gAudioStreamPreparedId = 0;
        gAudioStreamPreparingId = 0;
        gAudioStreamCurrentId = 0;
        gAudioStreamStartWhenPrepared = 0;
        gAudioActiveChannelMask = 0;
        gAudioStreamMusicFadeFlagB = 0;
        gAudioStreamMusicFadeFlagA = 0;
    }
    else
    {
        gAudioStreamPlaying = 0;
    }
}

static void AudioStream_CancelCallback(s32 result, DVDCommandBlock* block)
{
    (void)block;
    if (result == 0)
    {
        AISetStreamPlayState(AI_STREAM_STOP);
    }
    gAudioActiveChannelMask = 0;
    gAudioStreamPlaying = 0;
}

void AudioStream_SetVolume(volume)
u8 volume;
{
    gAudioStreamVolumeLeft = volume;
    gAudioStreamVolumeRight = volume;
    AISetStreamVolLeft(volume);
    AISetStreamVolRight(volume);
}

u8 AudioStream_IsPreparing(void)
{
    return gAudioStreamDvdState;
}

s32 AudioStream_GetCurrentId(void)
{
    return gAudioStreamCurrentId;
}

u32 AudioStream_GetMusicFadeFlagB(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos)
    {
        return 0;
    }
    return gAudioStreamMusicFadeFlagB;
}

u32 AudioStream_GetMusicFadeFlagA(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos)
    {
        return 0;
    }
    return gAudioStreamMusicFadeFlagA;
}

void AudioStream_Nop(int unused)
{
}

void AudioStream_StopAll(void)
{
    if (gAudioStreamDvdState != 0)
    {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(&gAudioStreamPreparedCommand,
                                 AudioStream_CancelPreparedCallback) == 0)
        {
            OSReport(sDvdCancelStreamWarning);
        }
        gAudioStreamPreparedId = 0;
        gAudioStreamPreparingId = 0;
        gAudioStreamCurrentId = 0;
        gAudioStreamStartWhenPrepared = 0;
        gAudioActiveChannelMask = 0;
        gAudioStreamMusicFadeFlagB = 0;
        gAudioStreamMusicFadeFlagA = 0;
    }

    if (gAudioStreamCurrentId != 0)
    {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(&gAudioStreamDvdBlockCurrent, AudioStream_CancelCallback) == 0)
        {
            OSReport(sDvdCancelStreamWarning);
            gAudioStreamPlaying = 0;
        }
    }
    else
    {
        gAudioStreamPlaying = 0;
    }

    gAudioStreamPreparedId = 0;
    gAudioStreamPreparingId = 0;
    gAudioStreamCurrentId = 0;
    gAudioStreamStartWhenPrepared = 0;
    gAudioActiveChannelMask = 0;
    gAudioStreamMusicFadeFlagB = 0;
    gAudioStreamMusicFadeFlagA = 0;
}
