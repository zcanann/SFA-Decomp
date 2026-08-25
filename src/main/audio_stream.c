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

u16 gSfxLoopedObjectSoundCount;
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

DVDCommandBlock gAudioStreamDvdBlockCurrent;

// AISetStreamPlayState() states

static void AudioStream_CancelCallback(s32 result, DVDCommandBlock* block);
static void AudioStream_CancelPreparedCallback(s32 result, DVDCommandBlock* block);
static void AudioStream_PrepareCallback(s32 result, DVDFileInfo* fileInfo);

void AudioStream_StopAll(void)
{
    if (gAudioStreamDvdState != 0)
    {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(&gAudioStreamDvdBlockPrepared.preparedCommand,
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

AudioDvdStreamContext gAudioStreamDvdBlockPrepared;

void AudioStream_Nop(int unused)
{
}

u32 AudioStream_GetMusicFadeFlagA(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos)
    {
        return 0;
    }
    return gAudioStreamMusicFadeFlagA;
}

u32 AudioStream_GetMusicFadeFlagB(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos)
    {
        return 0;
    }
    return gAudioStreamMusicFadeFlagB;
}

s32 AudioStream_GetCurrentId(void)
{
    return gAudioStreamCurrentId;
}

u8 AudioStream_IsPreparing(void)
{
    return gAudioStreamDvdState;
}

void AudioStream_SetVolume(volume)
u8 volume;
{
    gAudioStreamVolumeLeft = volume;
    gAudioStreamVolumeRight = volume;
    AISetStreamVolLeft(volume);
    AISetStreamVolRight(volume);
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

static void AudioStream_CancelPreparedCallback(s32 result, DVDCommandBlock* block)
{
    (void)result;
    (void)block;
    gAudioStreamDvdState = 0;
}

void AudioStream_CancelPrepared(void)
{
    AISetStreamVolLeft(0);
    AISetStreamVolRight(0);
    if (DVDCancelStreamAsync(&gAudioStreamDvdBlockPrepared.preparedCommand,
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
int AudioStream_Play(int id, void (*preparedCallback)(void))
{
    char path[64];
    u8 vol;
    AudioDvdStreamStorage* dvd[1];
    int* fadeTbl;
    StreamEntry* s;
    int count;
    int slot;
    int i;
    u8 stopped;

    dvd[0] = (AudioDvdStreamStorage*)&gAudioStreamDvdBlockCurrent;
    fadeTbl = gAudioStreamFadeTable;
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

    if (concatThreeStrings(path, (void*)0x40, (char*)fadeTbl + 0x3C, s->name, sAdpExtension) != 0)
    {
        if (DVDOpen(path, &dvd[0]->prepared.fileInfo) == 0)
        {
            return 0;
        }

        if (gAudioStreamCurrentId != 0)
        {
            AISetStreamVolLeft(0);
            AISetStreamVolRight(0);
            if (DVDCancelStreamAsync(&dvd[0]->currentCommand, AudioStream_CancelCallback) == 0)
            {
                OSReport((char*)fadeTbl + 0xC);
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

        gAudioStreamMusicFadeFlagA = fadeTbl[s->fadeModeA] == 0 ? 0 : 1;
        gAudioStreamMusicFadeFlagB = fadeTbl[s->fadeModeB] == 0 ? 0 : 1;
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
        DVDPrepareStreamAsync(&dvd[0]->prepared.fileInfo, 0, 0, AudioStream_PrepareCallback);
        DVDStopStreamAtEndAsync(&dvd[0]->prepared.stopAtEndCommand, NULL);
        return 1;
    }
    return 0;
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

void AudioStream_SetDefaultVolume(volume)
u8 volume;
{
    gAudioStreamDefaultVolume = volume;
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


void Sfx_ClearLoopedObjectSounds(void)
{
    gSfxLoopedObjectSoundCount = 0;
}


void Sfx_UpdateLoopedObjectSounds(void)
{
    SfxLoopedObjectSoundTable* table = (SfxLoopedObjectSoundTable*)gSfxLoopedObjectSoundFlags;
    u8* fp;
    GameObject** op;
    u16* ip;
    u16 index;
    s16 i;
    int index2;
    GameObject* obj;
    int removeSound;
    u16 sz;

    i = (s16)(gSfxLoopedObjectSoundCount - 1);
    fp = table->flags + i;
    op = (GameObject**)table + i;
    op += SFX_LOOPED_OBJECT_TABLE_OBJECT_COLUMN;
    ip = (u16*)table->ids + i;
    for (; i >= 0; i--)
    {
        removeSound = 0;
        if (((*fp & SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE) != 0) && ((*fp & SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN) == 0))
        {
            removeSound = 1;
        }
        obj = *op;
        if (((obj != 0) && ((obj->objectFlags & SFX_LOOPED_OBJECT_STOP_FLAG) != 0)) || removeSound)
        {
            Sfx_StopFromObject(obj, *ip);
            gSfxLoopedObjectSoundCount--;
            sz = (u16)((gSfxLoopedObjectSoundCount - (index = i)) << 2);
            memmove((u32*)table->objects + index, (u32*)table->objects + (index2 = index + 1), sz);
            memmove((u16*)table->ids + index, (u16*)table->ids + index2,
                    (u16)((gSfxLoopedObjectSoundCount - index) << 1));
            memmove(table->flags + index, table->flags + index2, (u16)(gSfxLoopedObjectSoundCount - index));
        }
        else
        {
            *fp &= ~SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
        }
        fp--;
        op--;
        ip--;
    }

    {
        s16 i2;
        u16* ip2;
        GameObject** op2;
        for (i2 = 0, ip2 = table->ids, op2 = table->objects; i2 < gSfxLoopedObjectSoundCount; i2++)
        {
            if (Sfx_IsPlayingFromObject(*op2, *ip2) == 0)
            {
                Sfx_PlayFromObject(*op2, *ip2);
            }
            ip2++;
            op2++;
        }
    }
}



void Sfx_KeepAliveLoopedObjectSoundLimited(GameObject* obj, u16 sfxId, u16 limit)
{
    SfxLoopedObjectSoundTable* table = (SfxLoopedObjectSoundTable*)gSfxLoopedObjectSoundFlags;
    u8* flags = table->flags;
    s32 count;
    u16 sameSfxCount;
    u16* ip;
    GameObject** op;
    GameObject** objects;
    u16* ids;
    s16 j;
    int found;
    s16 i;

    count = gSfxLoopedObjectSoundCount;
    sameSfxCount = 0;
    i = 0;
    ids = table->ids;
    ip = ids;
    objects = table->objects;
    op = objects;
    for (; i < count; i++)
    {
        if (sfxId == *ip)
        {
            if (limit != 0)
            {
                sameSfxCount++;
            }
            if (*op == obj)
            {
                flags[i] |= SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE | SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
                return;
            }
        }
        ip++;
        op++;
    }

    if (sameSfxCount <= limit)
    {
        for (j = 0; j < count || (found = 0, 0); j++)
        {
            if (*objects == obj && sfxId == *ids)
            {
                found = 1;
                break;
            }
            objects++;
            ids++;
        }

        if ((found == 0) && (count != sizeof(table->flags)))
        {
            table->objects[count] = obj;
            table->ids[count] = sfxId;
            flags[count] = 0;
            gSfxLoopedObjectSoundCount++;
            Sfx_PlayFromObject(obj, sfxId);
        }
    }

    if ((u32)count != gSfxLoopedObjectSoundCount)
    {
        flags[count] |= SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE | SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
    }
}

void Sfx_KeepAliveLoopedObjectSound(GameObject* obj, u16 sfxId)
{
    Sfx_KeepAliveLoopedObjectSoundLimited(obj, sfxId, 0);
}

void Sfx_RemoveLoopedObjectSoundForObject(GameObject* obj)
{
    SfxLoopedObjectSoundTable* table = (SfxLoopedObjectSoundTable*)gSfxLoopedObjectSoundFlags;
    int index;
    int index2;
    s16 i;
    GameObject** op;
    u16 sz;

    i = (s16)(gSfxLoopedObjectSoundCount - 1);
    op = (GameObject**)table + i;
    op += SFX_LOOPED_OBJECT_TABLE_OBJECT_COLUMN;
    for (; i >= 0; i--)
    {
        if (*op == obj)
        {
            Sfx_StopFromObject(obj, table->ids[i]);
            gSfxLoopedObjectSoundCount--;
            sz = (u16)((gSfxLoopedObjectSoundCount - (index = (u16)i)) << 2);
            memmove((u32*)table->objects + index, (u32*)table->objects + (index2 = index + 1), sz);
            memmove((u16*)table->ids + index, (u16*)table->ids + index2,
                    (u16)((gSfxLoopedObjectSoundCount - index) << 1));
            memmove(table->flags + index, table->flags + index2, (u16)(gSfxLoopedObjectSoundCount - index));
            return;
        }
        op--;
    }
}

void Sfx_RemoveLoopedObjectSound(GameObject* obj, u16 sfxId)
{
    SfxLoopedObjectSoundTable* table = (SfxLoopedObjectSoundTable*)gSfxLoopedObjectSoundFlags;
    GameObject** op;
    u16* ip;
    s16 i;
    int index;
    int index2;
    u16 sz;

    i = (s16)(gSfxLoopedObjectSoundCount - 1);
    op = (GameObject**)table + i;
    op += SFX_LOOPED_OBJECT_TABLE_OBJECT_COLUMN;
    ip = (u16*)table->ids + i;
    for (; i >= 0; i--)
    {
        if (*op == obj && sfxId == *ip)
        {
            gSfxLoopedObjectSoundCount--;
            sz = (u16)((gSfxLoopedObjectSoundCount - (index = (u16)i)) << 2);
            memmove((u32*)table->objects + index, (u32*)table->objects + (index2 = index + 1), sz);
            memmove((u16*)table->ids + index, (u16*)table->ids + index2,
                    (u16)((gSfxLoopedObjectSoundCount - index) << 1));
            memmove(table->flags + index, table->flags + index2, (u16)(gSfxLoopedObjectSoundCount - index));
            Sfx_StopFromObject(obj, sfxId);
            return;
        }
        op--;
        ip--;
    }
}


void Sfx_AddLoopedObjectSound(GameObject* obj, u16 sfxId)
{
    SfxLoopedObjectSoundTable* table;
    s16 i;
    GameObject** objectIt;
    u16* idIt;
    s32 count;
    int found;

    table = (SfxLoopedObjectSoundTable*)gSfxLoopedObjectSoundFlags;
    i = 0;
    objectIt = table->objects;
    idIt = table->ids;
    count = gSfxLoopedObjectSoundCount;
    for (; i < count || (found = 0, 0); i++)
    {
        if ((*objectIt == obj) && (sfxId == *idIt))
        {
            found = 1;
            break;
        }
        objectIt++;
        idIt++;
    }

    if ((found == 0) && (count != sizeof(table->flags)))
    {
        table->objects[count] = obj;
        table->ids[count] = sfxId;
        table->flags[count] = 0;
        gSfxLoopedObjectSoundCount++;
        Sfx_PlayFromObject(obj, sfxId);
    }
}

int gAudioStreamFadeTable[] = {0, 2, 4};
char sDvdCancelStreamWarning[0x3C] = "WARNING:DVDCancelStreamAsync returned FALSE\012\000\000\000\000/streams/";

GameObject* gSfxLoopedObjectSoundObjects[0x80];
u16 gSfxLoopedObjectSoundIds[0x80];
u8 gSfxLoopedObjectSoundFlags[0x80];
