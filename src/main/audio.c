#include "main/engine_shared.h"
#include "main/game_object.h"

void audioStopByMask(int mask)
{
    if ((mask & 4) != 0)
    {
        Sfx_StopAllObjectSounds();
    }
    if ((mask & 1) != 0)
    {
        streamFn_8000a380(1, 1, 0);
    }
    if ((mask & 2) != 0)
    {
        streamFn_8000a380(2, 1, 0);
    }
    if ((mask & 8) != 0)
    {
        AudioStream_StopCurrent();
    }
}

void audioReset(void)
{
    if (gAudioInitStarted != 0)
    {
        sndQuit();
    }
    AIReset();
}

#pragma dont_inline on
int audioIsResetting(void)
{
    return gAudioResetting;
}
#pragma dont_inline reset

void audioStopAll(void)
{
    gAudioResetting = 1;
    Sfx_StopAllObjectSounds();
    streamFn_8000a380(1, 1, 0);
    streamFn_8000a380(2, 1, 0);
    AudioStream_StopCurrent();
    gAudioManagedChannelMask &= ~0xfU;
    gAudioResetting = 1;
    if ((gAttractMovieState == 2) || (gAttractMovieState == 3))
    {
        Movie_SetVolumeFade(0, 500);
    }
    AudioStream_CancelPrepared();
}

void audioUpdate(void)
{
    Music_Update();
    Sfx_UpdateObjectSounds();
    AudioStream_UpdateFadeTimer();
}

#pragma dont_inline on
u32 audioFlagFn_8000a188(u32 mask)
{
    s32 managed = gAudioManagedChannelMask & mask;
    if (managed == 0)
    {
        return 1;
    }
    return (gAudioActiveChannelMask & mask) != 0;
}
#pragma dont_inline reset

void audioFree(void* ptr)
{
    mm_free(ptr);
}

void* _audioAlloc(u32 size)
{
    return mmAlloc(size, 0xb, NULL);
}

void Music_ChannelLoadedCallback(MusicBank* bank, MusicChannel* channel, MusicTrigParam* trigger)
{
    MusicSeqStartParams params = gMusicSeqStartParamsDefault;

    if (channel != NULL)
    {
        if (channel->status == 5)
        {
            mm_free(channel->bankData);
            channel->field_0 = -1;
            channel->seqHandle = -1;
            channel->bankData = NULL;
            channel->voiceId = 0xff;
            channel->status = 0;
            channel->field_12 = 0;
            channel->field_20 = lbl_803DE560;
        }
        else
        {
            int seqHandle;
            int voice;
            if (trigger->field_6 != -1)
            {
                params.field_c = trigger->field_6;
                params.flags |= 2;
            }
            if (trigger->field_c != -1)
            {
                voice = trigger->field_c;
            }
            else
            {
                voice = 0x7f;
            }
            params.field_10 = 0;
            params.field_e = 0;
            params.flags |= 4;
            seqHandle = sndSeqPlayEx(bank->field_2, trigger->field_2, channel->bankData, &params, 0);
            sndSeqVolume(voice, 0x1f4, seqHandle, 0);
            channel->status = 1;
            channel->seqHandle = seqHandle;
            channel->voiceId = synthResolveHandle(seqHandle);
        }
    }
}

int Sfx_ReadTriggerParams(SfxTriggerFull* trigger, u16* outSfxId, u8* outVol, f32* outF6,
                          f32* outF7, f32* outF8, int* outI9, int* outI10, int* outI11)
{
    int idx;
    int selector;

    if (trigger == NULL || trigger->f_count == 0)
    {
        return 0;
    }

    selector = randomGetRange(1, trigger->selectRange);
    if (trigger->id == 0xab)
    {
        if (trigger->f_curIdx == 0)
        {
            trigger->f_curIdx = 1;
        }
        else
        {
            trigger->f_curIdx = 0;
        }
        idx = trigger->f_curIdx;
    }
    else
    {
        idx = 0;
        while (selector > trigger->weights[idx])
        {
            selector -= trigger->weights[idx];
            idx++;
        }
        if (trigger->f_curIdx == idx)
        {
            idx++;
            if (idx >= trigger->f_count)
            {
                idx = 0;
            }
        }
    }
    trigger->f_curIdx = idx;

    *outSfxId = trigger->sfxIds[idx];
    if (*outSfxId == 0)
    {
        return 0;
    }

    {
        int hi;
        int vr = trigger->volRand;
        if ((u32)vr != 0)
        {
            hi = trigger->volBase + randomGetRange(0, vr);
            *outVol = hi - randomGetRange(0, vr);
        }
        else
        {
            *outVol = trigger->volBase;
        }
    }
    {
        int pr = trigger->pitchRand;
        if ((u32)pr != 0)
        {
            int hi = trigger->pitchBase + randomGetRange(0, pr);
            *outF6 = (f32)(hi - randomGetRange(0, pr));
        }
        else
        {
            *outF6 = (f32)(u32)
            trigger->pitchBase;
        }
    }
    *outF7 = (f32)(u32)
    trigger->field_6;
    *outF8 = (f32)(u32)
    trigger->field_8;
    *outI9 = (&gSfxTriggerExtraTable)[trigger->e_tableIdx];
    *outI10 = trigger->e_bit0;
    *outI11 = trigger->e_bit3;
    return 1;
}

#pragma dont_inline on
SfxTrigger* Sfx_FindTrigger(u16 id)
{
    SfxTrigger* low = (SfxTrigger*)gSfxTriggersData;
    SfxTrigger* high = (SfxTrigger*)gSfxTriggersData + gSfxTriggersCount;
    int key = id;
    SfxTriggerCacheEntry* c = &gSfxTriggerLookupCache[key & 0xf];

    if (c->key == key)
    {
        return (SfxTrigger*)gSfxTriggersData + c->index;
    }
    while (low < high)
    {
        SfxTrigger* mid = low + (high - low) / 2;
        if (mid->id > key)
        {
            high = mid;
        }
        else if (mid->id < key)
        {
            low = mid + 1;
        }
        else
        {
            c->key = id;
            c->index = mid - (SfxTrigger*)gSfxTriggersData;
            return mid;
        }
    }
    return NULL;
}
#pragma dont_inline reset

static inline SfxObjectChannel* Sfx_FindFreeObjectChannel(void)
{
    SfxObjectChannel* ch = (SfxObjectChannel*)(int)gSfxObjectChannels;
    s32 i;
    for (i = SFX_OBJECT_CHANNEL_COUNT - 1; i >= 0; i--)
    {
        if (ch->handle == (u32) - 1)
        {
            return ch;
        }
        ch++;
    }
    return NULL;
}

SfxObjectChannel* Sfx_AllocObjectChannel(a, b, pitch, c, d)
s16 a;
int b;
double pitch;
int c;

int d;
{
    extern f32 lbl_803DE594;
    SfxObjectChannel* ch;
    s32 i;
    u32 handle;

    if ((int)audioFlagFn_8000a188(4) != 0)
    {
        return 0;
    }

    ch = Sfx_FindFreeObjectChannel();
    if (ch == NULL)
    {
        return 0;
    }

    handle = sndFXStartEx(a, b, c, 0);
    if (handle == (u32) - 1)
    {
        goto fail;
    }
    if (gSfxGlobalCtrlLevel != 0 && d == 0)
    {
        sndFXCtrl(handle, 0x5b, gSfxGlobalCtrlLevel);
    }

    ch->object = 0;
    ch->channelMask = 0;
    ch->paused = 0;
    ch->hasPosition = 0;
    ch->tracksObjectPosition = 0;
    ch->handle = handle;
    {
        f32 fz = lbl_803DE570;
        ch->x = fz;
        ch->y = fz;
        ch->z = fz;
    }
    ch->field08 = a;
    ch->volume = 0x64;
    ch->field20 = lbl_803DE590;
    ch->field24 = lbl_803DE594;
    ch->globalCtrlDisabled = d;

    {
        u64 age = gSfxObjectChannelAgeLo | ((u64)gSfxObjectChannelAgeHi << 32);
        u64 next = age + 1;
        gSfxObjectChannelAgeLo = next;
        gSfxObjectChannelAgeHi = (u32)(next >> 32);
        ch->age = age;
    }
    return ch;
fail:
    ch->handle = (u32) - 1;
    return 0;
}

void Sfx_RotateVectorByAngles(s16 angX, s16 angY, s16 angZ, f32* v)
{
    f32 x = v[0];
    f32 y = v[1];
    f32 z = v[2];
    f32 ra = gAudioPi * angX / gAudioAngleToRadDivisor;
    f32 ca = mathSinf(ra);
    f32 rb = gAudioPi * angY / gAudioAngleToRadDivisor;
    f32 cb = mathSinf(rb);
    f32 rc = gAudioPi * angZ / gAudioAngleToRadDivisor;
    f32 cc = mathSinf(rc);
    f32 sa = mathCosf(ra);
    f32 sb = mathCosf(rb);
    f32 sc = mathCosf(rc);
    f32 t0, t1, A, p, B;

    t0 = x * ca;
    t1 = z * ca;
    A = x * sa;
    p = z * sa;
    A = A + t1;
    p = p - t0;
    t0 = y * cb;
    t1 = p * cb;
    B = y * sb;
    p = p * sb;
    B = B - t1;
    p = p + t0;
    t0 = A * cc;
    t1 = B * cc;
    A = A * sc;
    B = B * sc;
    A = A - t1;
    B = B + t0;

    v[0] = A;
    v[1] = B;
    v[2] = p;
}

#pragma dont_inline on
#pragma opt_common_subs off
f32 Sfx_GetListenerRelativeDistance(f32* soundPos, f32* outDelta)
{
    f32 v[3];
    f32 t;
    double t2;
    f32* listener;
    void* player = Obj_GetPlayerObject();
    void* slot = Camera_GetCurrentViewSlot();
    int seqNo = getCurSeqNo();

    if (player != NULL && seqNo == 0)
    {
        listener = &((GameObject*)player)->anim.worldPosX;
    }
    else
    {
        if (slot == NULL)
        {
            goto retDefault;
        }
        if (player != NULL)
        {
            PSVECSubtract((f32*)((u8*)slot + 0x44), &((GameObject*)player)->anim.worldPosX, v);
            t = (PSVECMag(v) - lbl_803DE5B4) / lbl_803DE5B8;
            if (lbl_803DE5C0 < (t > lbl_803DE5C8 ? t : lbl_803DE5C8))
            {
                t2 = lbl_803DE5C0;
            }
            else
            {
                t2 = (t > lbl_803DE5C8 ? t : lbl_803DE5C8);
            }
            PSVECScale(v, v, t2);
            PSVECAdd(&((GameObject*)player)->anim.worldPosX, v, v);
            listener = v;
        }
        else
        {
            listener = (f32*)((u8*)slot + 0x44);
        }
        goto common;
    retDefault:
        return lbl_803DE570;
    }
common:
    PSVECSubtract(listener, soundPos, outDelta);
    return PSVECMag(outDelta);
}
#pragma opt_common_subs reset
#pragma dont_inline reset

void AudioStream_StopAll(void)
{
    if (gAudioStreamDvdState != 0)
    {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(gAudioStreamDvdBlockPrepared, fn_8000D0B4) == 0)
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
        if (DVDCancelStreamAsync(gAudioStreamDvdBlockCurrent, AudioStream_CancelCallback) == 0)
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

#pragma dont_inline on
u32 AudioStream_GetMusicFadeFlagA(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos)
    {
        return 0;
    }
    return gAudioStreamMusicFadeFlagA;
}
#pragma dont_inline reset

#pragma dont_inline on
u32 AudioStream_GetMusicFadeFlagB(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos)
    {
        return 0;
    }
    return gAudioStreamMusicFadeFlagB;
}
#pragma dont_inline reset

u32 AudioStream_GetCurrentId(void)
{
    return gAudioStreamCurrentId;
}

u8 AudioStream_IsPreparing(void)
{
    return gAudioStreamDvdState;
}

#pragma dont_inline on
void AudioStream_SetVolume(u8 volume)
{
    gAudioStreamVolumeLeft = volume;
    gAudioStreamVolumeRight = volume;
    AISetStreamVolLeft(volume);
    AISetStreamVolRight(volume);
}
#pragma dont_inline reset

void AudioStream_CancelCallback(s32 result)
{
    if (result == 0)
    {
        AISetStreamPlayState(0);
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
        if (DVDCancelStreamAsync(gAudioStreamDvdBlockCurrent, AudioStream_CancelCallback) == 0)
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

void fn_8000D0B4(void)
{
    gAudioStreamDvdState = 0;
}

void AudioStream_CancelPrepared(void)
{
    AISetStreamVolLeft(0);
    AISetStreamVolRight(0);
    if (DVDCancelStreamAsync(gAudioStreamDvdBlockPrepared, fn_8000D0B4) == 0)
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
                AISetStreamPlayState(1);
                gAudioStreamPlaying = 1;
                gAudioStreamPos = lbl_803DE5D0;
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

void AudioStream_UpdateFadeTimer(void)
{
    if (gAudioStreamCurrentId != 0)
    {
        f32 position = gAudioStreamPos;
        gAudioStreamPos = position + (timeDelta / gAudioStreamFramesPerSecond);
    }
    else
    {
        gAudioStreamPos = lbl_803DE5D0;
    }
}

#pragma dont_inline on
void AudioStream_SetDefaultVolume(u8 volume)
{
    gAudioStreamDefaultVolume = volume;
}
#pragma dont_inline reset

#pragma dont_inline on
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
#pragma dont_inline reset

void AudioStream_PrepareCallback(void)
{
    if (getGameState() != 1)
    {
        gAudioStreamDvdState = 0;
        return;
    }
    gAudioStreamPreparedId = gAudioStreamPreparingId;
    gAudioStreamPreparingId = 0;
    if (gAudioStreamStartWhenPrepared != 0)
    {
        if (getGameState() == 1)
        {
            AISetStreamVolLeft(gAudioStreamVolumeLeft);
            AISetStreamVolRight(gAudioStreamVolumeRight);
            AISetStreamPlayState(1);
            gAudioStreamPlaying = 1;
            gAudioStreamPos = lbl_803DE5D0;
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
    else if (gAudioStreamPreparedCallback != NULL)
    {
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
            AISetStreamPlayState(0);
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
    SfxLoopedObjectSoundTable* table = &gSfxLoopedObjectSoundFlags;
    int index;
    int index2;
    u8* fp;
    u32* op;
    u16* ip;
    s16 i;
    u32 obj;
    int removeSound;
    u16 sz;

    i = (s16)(gSfxLoopedObjectSoundCount - 1);
    fp = &table->flags[i];
    op = (u32*)&(&table->flags[i << 2])[384];
    ip = (u16*)&(&table->flags[i << 1])[128];
    for (; i >= 0; i--)
    {
        removeSound = 0;
        if (((*fp & SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE) != 0) &&
            ((*fp & SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN) == 0))
        {
            removeSound = 1;
        }
        obj = *op;
        if (((obj != 0) && ((((GameObject*)obj)->objectFlags & SFX_LOOPED_OBJECT_STOP_FLAG) != 0)) || removeSound)
        {
            Sfx_StopFromObject(obj, *ip);
            gSfxLoopedObjectSoundCount--;
            sz = (u16)((gSfxLoopedObjectSoundCount - (index = (u16)i)) << 2);
            memmove(&table->flags[(index << 2) + 384],
                    &table->flags[((index2 = index + 1) << 2) + 384], sz);
            memmove(&table->flags[(index << 1) + 128], &table->flags[(index2 << 1) + 128],
                    (u16)((gSfxLoopedObjectSoundCount - index) << 1));
            memmove(&table->flags[index], &table->flags[index2],
                    (u16)(gSfxLoopedObjectSoundCount - index));
        }
        else
        {
            *fp = *(u8*)(int)fp & ~SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
        }
        fp--;
        op--;
        ip--;
    }

    {
        u16* ip2;
        u32* op2;
        for (i = 0, ip2 = table->ids, op2 = table->objects; i < gSfxLoopedObjectSoundCount; i++)
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

void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit)
{
    SfxLoopedObjectSoundTable* table = &gSfxLoopedObjectSoundFlags;
    u8* flags = table->flags;
    u16 count = gSfxLoopedObjectSoundCount;
    u16 sameSfxCount = 0;
    s16 i = 0;
    u16* ids = table->ids;
    u16* ip = ids;
    u32* objects = table->objects;
    u32* op = objects;
    s16 j;
    int found;

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
        for (j = 0; j < count; j++)
        {
            if ((*objects == obj) && (sfxId == *ids))
            {
                found = 1;
                goto checked;
            }
            objects++;
            ids++;
        }
        found = 0;
    checked:
        if ((found == 0) && (count != SFX_LOOPED_OBJECT_SOUND_COUNT))
        {
            table->objects[count] = obj;
            table->ids[count] = sfxId;
            flags[count] = 0;
            gSfxLoopedObjectSoundCount++;
            Sfx_PlayFromObject(obj, sfxId);
        }
    }

    if (count != gSfxLoopedObjectSoundCount)
    {
        flags[count] |= SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE | SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
    }
}

void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId)
{
    Sfx_KeepAliveLoopedObjectSoundLimited(obj, sfxId, 0);
}

void Sfx_RemoveLoopedObjectSoundForObject(u32 obj)
{
    SfxLoopedObjectSoundTable* table = &gSfxLoopedObjectSoundFlags;
    s16 i;
    u32* op;
    int index;
    int index2;
    u16 sz;

    i = (s16)(gSfxLoopedObjectSoundCount - 1);
    op = (u32*)&(&table->flags[i << 2])[384];
    for (; i >= 0; i--)
    {
        if (*op == obj)
        {
            Sfx_StopFromObject(obj, table->ids[i]);
            gSfxLoopedObjectSoundCount--;
            sz = (u16)((gSfxLoopedObjectSoundCount - (index = (u16)i)) << 2);
            memmove(&table->flags[(index << 2) + 384],
                    &table->flags[((index2 = index + 1) << 2) + 384], sz);
            memmove(&table->flags[(index << 1) + 128], &table->flags[(index2 << 1) + 128],
                    (u16)((gSfxLoopedObjectSoundCount - index) << 1));
            memmove(&table->flags[index], &table->flags[index2],
                    (u16)(gSfxLoopedObjectSoundCount - index));
            return;
        }
        op--;
    }
}

void Sfx_RemoveLoopedObjectSound(u32 obj, u32 sfxId)
{
    SfxLoopedObjectSoundTable* table = &gSfxLoopedObjectSoundFlags;
    u16 sfx16;
    u32* op;
    u16* ip;
    s16 i;
    int index;
    int index2;
    u16 sz;

    i = (s16)(gSfxLoopedObjectSoundCount - 1);
    op = (u32*)&table->flags[i << 2];
    op += 96;
    ip = (u16*)&table->flags[i << 1];
    ip += 64;
    sfx16 = sfxId;
    for (; i >= 0; i--)
    {
        if (*op == obj && sfx16 == *ip)
        {
            gSfxLoopedObjectSoundCount--;
            sz = (u16)((gSfxLoopedObjectSoundCount - (index = (u16)i)) << 2);
            memmove(&table->flags[(index << 2) + 384],
                    &table->flags[((index2 = index + 1) << 2) + 384], sz);
            memmove(&table->flags[(index << 1) + 128], &table->flags[(index2 << 1) + 128],
                    (u16)((gSfxLoopedObjectSoundCount - index) << 1));
            memmove(&table->flags[index], &table->flags[index2],
                    (u16)(gSfxLoopedObjectSoundCount - index));
            Sfx_StopFromObject(obj, sfxId);
            return;
        }
        op--;
        ip--;
    }
}

void Sfx_AddLoopedObjectSound(u32 obj, u32 sfxId)
{
    SfxLoopedObjectSoundTable* table;
    u32* objectIt;
    u16* idIt;
    s16 i;
    u16 count;
    int found;

    table = &gSfxLoopedObjectSoundFlags;
    i = 0;
    objectIt = table->objects;
    idIt = table->ids;
    count = gSfxLoopedObjectSoundCount;
    for (; i < count; i++)
    {
        if ((*objectIt == obj) && ((u16)sfxId == *idIt))
        {
            found = 1;
            goto checked;
        }
        objectIt++;
        idIt++;
    }
    found = 0;
checked:
    if ((found == 0) && (count != SFX_LOOPED_OBJECT_SOUND_COUNT))
    {
        table->objects[count] = obj;
        table->ids[count] = sfxId;
        table->flags[count] = 0;
        gSfxLoopedObjectSoundCount++;
        Sfx_PlayFromObject(obj, sfxId);
    }
}

int return0x64_8000A378(void) { return 0x64; }

void doNothing_8000CF54(void)
{
}

#pragma dont_inline on
s32 Music_GetActivePriority(void)
{
    return gMusicActivePriority;
}
#pragma dont_inline reset

s32 Sfx_IsPlayingFromObjectChannel(u32 obj, u32 channel)
{
    SfxObjectChannel* objectChannel;

    if (((u8)channel == 0) || (obj == 0))
    {
        objectChannel = NULL;
    }
    else
    {
        objectChannel = Sfx_FindObjectChannel(obj, channel, 0, 0);
    }

    if (objectChannel != NULL)
    {
        return 1;
    }
    return 0;
}

s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId)
{
    SfxObjectChannel* objectChannel;

    if ((u16)sfxId != 0)
    {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 0);
    }
    else
    {
        objectChannel = NULL;
    }

    if (objectChannel != NULL)
    {
        return 1;
    }
    return 0;
}

#pragma dont_inline on
void Sfx_StopAllObjectSounds(void)
{
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do
    {
        if (objectChannel->handle != (u32) - 1)
        {
            sndFXKeyOff(objectChannel->handle);
            objectChannel->handle = (u32) - 1;
        }
        objectChannel++;
    }
    while (i-- != 0);
}
#pragma dont_inline reset

void audioFn_8000b694(u32 value)
{
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    gSfxGlobalCtrlLevel = (u8)(value * 5);
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do
    {
        if ((objectChannel->handle != (u32) - 1) && (objectChannel->globalCtrlDisabled == 0))
        {
            sndFXCtrl(objectChannel->handle, 0x5B, gSfxGlobalCtrlLevel);
        }
        objectChannel++;
    }
    while (i-- != 0);
}

void Sfx_SetObjectSoundsPaused(s32 paused)
{
    u8 pausedByte;
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    pausedByte = paused;

    do
    {
        if (objectChannel->handle != (u32) - 1)
        {
            if (paused != 0)
            {
                sndFXCtrl(objectChannel->handle, 7, 0);
            }
            else if (objectChannel->paused != 0)
            {
                sndFXCtrl(objectChannel->handle, 7, objectChannel->volume);
            }
            objectChannel->paused = pausedByte;
        }
        objectChannel++;
    }
    while (i-- != 0);
}

void Sfx_StopObjectChannel(u32 obj, u32 channel)
{
    SfxObjectChannel* objectChannel;

    if (((u8)channel == 0) || (obj == 0))
    {
        objectChannel = NULL;
    }
    else
    {
        objectChannel = Sfx_FindObjectChannel(obj, channel, 0, 0);
    }

    if (objectChannel != NULL)
    {
        sndFXKeyOff(objectChannel->handle);
        objectChannel->handle = (u32) - 1;
    }
}

void Sfx_StopFromObject(u32 obj, u32 sfxId)
{
    SfxObjectChannel* objectChannel;

    if ((u16)sfxId != 0)
    {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 0);
    }
    else
    {
        objectChannel = NULL;
    }

    if (objectChannel != NULL)
    {
        sndFXKeyOff(objectChannel->handle);
        objectChannel->handle = (u32) - 1;
    }
}

void Sfx_SetObjectChannelVolume(u32 obj, u32 channel, u8 volume, f32 volumeScale)
{
    u8 volumeByte;
    SfxObjectChannel* objectChannel;

    volumeByte = volume;
    if (((u8)channel == 0) || (obj == 0))
    {
        objectChannel = NULL;
    }
    else
    {
        objectChannel = Sfx_FindObjectChannel(obj, channel, 0, 2);
    }

    if (objectChannel != NULL)
    {
        if (volumeByte != 0xFE)
        {
            u32 ctrlVolume;

            if (volumeByte == 0xFF)
            {
                volumeByte = 100;
            }
            objectChannel->volume = volumeByte;
            if (objectChannel->hasPosition != 0)
            {
                Sfx_UpdateObjectChannel3D(objectChannel);
            }
            else
            {
                if (objectChannel->paused != 0)
                {
                    ctrlVolume = 0;
                }
                else
                {
                    ctrlVolume = volumeByte;
                }
                sndFXCtrl(objectChannel->handle, 7, (u8)ctrlVolume);
            }
        }

        if (volumeScale < lbl_803DE570)
        {
            volumeScale = lbl_803DE570;
        }
        if (volumeScale > lbl_803DE574)
        {
            volumeScale = lbl_803DE574;
        }
        sndFXCtrl14(objectChannel->handle, 0x80, (s32)(lbl_803DE578 * volumeScale));
    }
}

void Sfx_SetObjectSfxVolume(u32 obj, u32 sfxId, u8 volume, f32 volumeScale)
{
    u8 volumeByte;
    SfxObjectChannel* objectChannel;

    volumeByte = volume;
    if ((u16)sfxId != 0)
    {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 2);
    }
    else
    {
        objectChannel = NULL;
    }

    if (objectChannel != NULL)
    {
        if (volumeByte != 0xFE)
        {
            u32 ctrlVolume;

            if (volumeByte == 0xFF)
            {
                volumeByte = 100;
            }
            objectChannel->volume = volumeByte;
            if (objectChannel->hasPosition != 0)
            {
                Sfx_UpdateObjectChannel3D(objectChannel);
            }
            else
            {
                if (objectChannel->paused != 0)
                {
                    ctrlVolume = 0;
                }
                else
                {
                    ctrlVolume = volumeByte;
                }
                sndFXCtrl(objectChannel->handle, 7, (u8)ctrlVolume);
            }
        }

        if (volumeScale < lbl_803DE570)
        {
            volumeScale = lbl_803DE570;
        }
        if (volumeScale > lbl_803DE574)
        {
            volumeScale = lbl_803DE574;
        }
        sndFXCtrl14(objectChannel->handle, 0x80, (s32)(lbl_803DE578 * volumeScale));
    }
}

void Sfx_UpdateObjectChannel3D(SfxObjectChannel* objectChannel)
{
    void* slot;
    f32 volf;
    int level;
    f32 near;
    f32 far;
    f32 dist;
    f32 delta[3];

    slot = Camera_GetCurrentViewSlot();
    if (slot == NULL)
    {
        return;
    }
    if (objectChannel == NULL)
    {
        return;
    }
    if (!objectChannel->hasPosition)
    {
        return;
    }
    volf = (f32)(u32)
    objectChannel->volume;
    level = volf;
    near = objectChannel->field20;
    far = objectChannel->field24;
    dist = Sfx_GetListenerRelativeDistance(&objectChannel->x, delta);
    if (dist > lbl_803DE598 * far)
    {
        sndFXKeyOff(objectChannel->handle);
        objectChannel->handle = (u32) - 1;
        return;
    }
    Sfx_RotateVectorByAngles(0, 0, -*(s16*)((u8*)slot + 0x54), delta);
    Sfx_RotateVectorByAngles(*(s16*)slot, 0, 0, delta);
    Sfx_RotateVectorByAngles(0, -*(s16*)((u8*)slot + 0x52), 0, delta);
    if (dist > lbl_803DE59C)
    {
        f32 scale;
        int pan;
        int fx;

        if (dist < near)
        {
            level = (int)(f64)volf;
        }
        else if (dist > far)
        {
            level = 1;
        }
        else
        {
            level = (int)(volf * (lbl_803DE574 - (dist - near) / (far - near)));
            if (level < 1)
            {
                level = 1;
            }
            else if ((f32)level > volf)
            {
                level = (int)(f64)volf;
            }
        }
        scale = lbl_803DE5A0 / dist;
        delta[0] = delta[0] * scale;
        delta[1] = delta[1] * scale;
        delta[2] = delta[2] * scale;
        pan = (int)(gSfxPanScale * delta[0] + gSfxPanCenter);
        if (pan > 0x7f)
        {
            pan = 0x7f;
        }
        else if (pan < 0)
        {
            pan = 0;
        }
        fx = (int)(*(f32*)&gSfxPanScale * delta[2] + *(f32*)&gSfxPanCenter);
        if (fx > 0x7f)
        {
            fx = 0x7f;
        }
        else if (fx < 0)
        {
            fx = 0;
        }
        sndFXCtrl(objectChannel->handle, 0xa, (u8)pan);
        sndFXCtrl(objectChannel->handle, 0x83, (u8)fx);
        sndFXCtrl(objectChannel->handle, 7, (u8)(objectChannel->paused ? 0 : level));
    }
    else
    {
        int v;
        if (objectChannel->paused)
        {
            v = 0;
        }
        else
        {
            v = level;
        }
        sndFXCtrl(objectChannel->handle, 7, (u8)v);
    }
}

void Sfx_PlayFromObjectEx(u32 obj, f32* pos, u32 channel, u16 sfxId)
{
    u16 outSfxId;
    u8 vol;
    f32 pitch;
    f32 f7;
    f32 f8;
    int i9;
    int i10;
    int i11;
    f32 delta[3];
    SfxObjectChannel* found;
    SfxObjectChannel* ch;
    int tracksObj;

    tracksObj = 0;
    if (!Sfx_ResolveObjectSfxId((int*)&obj, &sfxId))
    {
        return;
    }
    if (!Sfx_ReadTriggerParams((SfxTriggerFull*)Sfx_FindTrigger(sfxId), &outSfxId,
                               &vol, &pitch, &f7, &f8, &i9, &i10, &i11))
    {
        return;
    }
    if (obj != 0 && pos == NULL)
    {
        pos = &((GameObject*)obj)->anim.worldPosX;
        tracksObj = 1;
    }
    if (pos != NULL)
    {
        f32 maxDist = f8;
        if (!(Sfx_GetListenerRelativeDistance(pos, delta) <= maxDist))
        {
            return;
        }
    }
    if ((u8)channel != 0)
    {
        i9 = (u8)channel;
    }
    if (obj != 0 && i9 != 0)
    {
        if ((u8)i9 == 0 || obj == 0)
        {
            found = NULL;
        }
        else
        {
            found = Sfx_FindObjectChannel(obj, (u8)i9, 0, 0);
        }
        if (found != NULL)
        {
            if (i10 == 0)
            {
                return;
            }
            sndFXKeyOff(found->handle);
            found->handle = (u32) - 1;
        }
    }
    else
    {
        if (sfxId != 0)
        {
            found = Sfx_FindObjectChannel(obj, 0, sfxId, 1);
        }
        else
        {
            found = NULL;
        }
        if (found != NULL)
        {
            if (i10 != 0 || (int)gSfxObjectChannelMatchCount == 3)
            {
                sndFXKeyOff(found->handle);
                found->handle = (u32) - 1;
            }
        }
    }
    ch = Sfx_AllocObjectChannel(outSfxId, vol, pitch, 0x40, i11);
    if (ch == NULL)
    {
        return;
    }
    ch->sfxId = sfxId;
    ch->channelMask = i9;
    ch->object = obj;
    if (pos != NULL)
    {
        ch->field20 = f7;
        ch->field24 = f8;
        ch->hasPosition = 1;
        {
            int t = 0;
            if (tracksObj != 0 && i9 != 0)
            {
                t = 1;
            }
            ch->tracksObjectPosition = t;
        }
        ch->x = pos[0];
        ch->y = pos[1];
        ch->z = pos[2];
        Sfx_UpdateObjectChannel3D(ch);
    }
    else
    {
        ch->volume = 0x7f;
    }
}

void Sfx_PlayFromObjectChannel(u32 obj, u32 channel, u16 sfxId)
{
    Sfx_PlayFromObjectEx(obj, NULL, channel, sfxId);
}

void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u32 obj, u16 sfxId)
{
    f32 pos[3];

    pos[0] = x;
    pos[1] = y;
    pos[2] = z;
    Sfx_PlayFromObjectEx(obj, pos, 0, sfxId);
}

void Sfx_PlayFromObject(u32 obj, u16 sfxId)
{
    Sfx_PlayFromObjectEx(obj, NULL, 0, sfxId);
}

void Sfx_UpdateObjectSounds(void)
{
    SfxObjectChannel* objectChannel;
    s32 i;
    u32 globalCtrl;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do
    {
        if ((objectChannel->handle != (u32) - 1) && ((u32)sndFXCheck(objectChannel->handle) == (u32) - 1))
        {
            objectChannel->handle = (u32) - 1;
        }
        objectChannel++;
    }
    while (i-- != 0);

    if (GameBit_Get(0xCBB) != 0)
    {
        globalCtrl = 0xE;
    }
    else if (GameBit_Get(0xEFA) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (GameBit_Get(0xEFB) != 0)
    {
        globalCtrl = 0xD;
    }
    else if (GameBit_Get(0xEFD) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (GameBit_Get(0xA7F) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (GameBit_Get(0xEFC) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (GameBit_Get(0xEFE) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (GameBit_Get(0xDCF) != 0)
    {
        globalCtrl = 0xB;
    }
    else if (Music_GetActivePriority() <= 0x28)
    {
        globalCtrl = 0xC;
    }
    else
    {
        globalCtrl = 0;
    }

    if ((u8)globalCtrl != (s32)(gSfxGlobalCtrlLevel / 5))
    {
        objectChannel = gSfxObjectChannels;
        gSfxGlobalCtrlLevel = (u8)(globalCtrl * 5);
        i = SFX_OBJECT_CHANNEL_COUNT - 1;
        do
        {
            if ((objectChannel->handle != (u32) - 1) && (objectChannel->globalCtrlDisabled == 0))
            {
                sndFXCtrl(objectChannel->handle, 0x5B, gSfxGlobalCtrlLevel);
            }
            objectChannel++;
        }
        while (i-- != 0);
    }

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do
    {
        if ((objectChannel->handle != (u32) - 1) && (objectChannel->hasPosition != 0))
        {
            if (objectChannel->tracksObjectPosition != 0)
            {
                if ((((GameObject*)objectChannel->object)->objectFlags & SFX_LOOPED_OBJECT_STOP_FLAG) != 0)
                {
                    objectChannel->tracksObjectPosition = 0;
                }
                else
                {
                    objectChannel->x = ((GameObject*)objectChannel->object)->anim.worldPosX;
                    objectChannel->y = ((GameObject*)objectChannel->object)->anim.worldPosY;
                    objectChannel->z = ((GameObject*)objectChannel->object)->anim.worldPosZ;
                }
            }

            if ((objectChannel->tracksObjectPosition != 0) || (objectChannel->globalCtrlDisabled != 0))
            {
                Sfx_UpdateObjectChannel3D(objectChannel);
            }
        }
        objectChannel++;
    }
    while (i-- != 0);
}

#pragma dont_inline on
void Sfx_InitObjectChannels(void)
{
    SfxObjectChannel* objectChannel;
    s32 i;

    i = SFX_OBJECT_CHANNEL_COUNT;
    objectChannel = &gSfxObjectChannels[SFX_OBJECT_CHANNEL_COUNT];
    goto checkNextChannel;
setChannelFree:
    objectChannel->handle = (u32) - 1;
checkNextChannel:
    objectChannel--;
    if (i-- != 0)
    {
        goto setChannelFree;
    }

    gSfxObjectChannelAgeLo = 0;
    gSfxObjectChannelAgeHi = 0;
    objectChannel = gSfxObjectChannels;
    gSfxGlobalCtrlLevel = 0;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do
    {
        if ((objectChannel->handle != (u32) - 1) && (objectChannel->globalCtrlDisabled == 0))
        {
            sndFXCtrl(objectChannel->handle, 0x5B, gSfxGlobalCtrlLevel);
        }
        objectChannel++;
    }
    while (i-- != 0);
}
#pragma dont_inline reset

SfxObjectChannel* Sfx_FindObjectChannel(u32 obj, u32 channel, u32 sfxId, s32 mode)
{
    SfxObjectChannel* objectChannel = gSfxObjectChannels;
    SfxObjectChannel* bestChannel = NULL;
    u64 bestAge;
    int channelMask;
    s32 i;

    bestAge = (mode == 2) ? 0 : -1;
    gSfxObjectChannelMatchCount = 0;
    channelMask = (u8)channel;

    for (i = SFX_OBJECT_CHANNEL_COUNT; i != 0; i--)
    {
        if ((objectChannel->handle != (u32) - 1) &&
            ((obj == 0) || (objectChannel->object == obj)) &&
            (((u8)channel == 0) || ((objectChannel->channelMask & channelMask) != 0)) &&
            (((u16)sfxId == 0) || (objectChannel->sfxId == (u16)sfxId)))
        {
            gSfxObjectChannelMatchCount++;

            switch (mode)
            {
            case 0:
                return objectChannel;
            case 2:
                if (objectChannel->age > bestAge)
                {
                    bestAge = objectChannel->age;
                    bestChannel = objectChannel;
                }
                break;
            case 1:
            case 3:
                if (objectChannel->age < bestAge)
                {
                    bestAge = objectChannel->age;
                    bestChannel = objectChannel;
                }
                break;
            }

            if ((mode != 3) && ((int)gSfxObjectChannelMatchCount == 3))
            {
                return bestChannel;
            }
        }
        objectChannel++;
    }

    return bestChannel;
}

#pragma dont_inline on
int concatThreeStrings(char* dst, void* unused, const char* first, const char* second, const char* third)
{
    strcpy(dst, first);
    strcat(dst, second);
    strcat(dst, third);
    return 1;
}
#pragma dont_inline reset

void fn_80009008(void)
{
    gAudioArqRequestDone = 1;
}

void fn_80008EDC(TextCallbackEntry* p)
{
    int i;
    TextCallbackEntry* e = gAudioArqRequests;
    for (i = 0; i < 16; i++)
    {
        if (p == e)
        {
            e->fn(e->a, e->b, e->c);
            return;
        }
        e++;
    }
}

void audioSetVolumes(u8 volume, u16 time, int musicFlag, int fxFlag, int streamFlag)
{
    if (musicFlag != 0 || fxFlag != 0)
    {
        sndMasterVolume(volume, time, musicFlag, fxFlag);
    }
    if (streamFlag != 0)
    {
        AudioStream_SetVolume(volume);
        AudioStream_SetDefaultVolume(volume);
    }
}

void MIDIWADLoadedCallback(int status, void* fileInfo)
{
    if (status == -1)
    {
        OSReport(sMidiWadLoadedCallbackLoadError);
        DVDClose(fileInfo);
        mm_free(fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        mm_free(fileInfo);
        gAudioPendingLoadFlags &= ~0x800LL;
        gAudioCompletedLoadFlags |= 0x800;
    }
}

#pragma opt_strength_reduction off
int musicInitMidiWad(void)
{
    MusicTrackSlot* table;
    MusicChannel* ch;
    int track, j;
    MusicTrackSlot* found;
    u32 size;
    int arenaOffset;
    int saved;
    int i;

    if (!gMidiWadLoadStarted)
    {
        gMidiWadLoadStarted = 1;
        ch = gMusicChannels;
        for (i = 16; i != 0; i--)
        {
            ch->field_0 = -1;
            ch->seqHandle = -1;
            ch->bankData = NULL;
            ch->voiceId = 0xff;
            ch->status = 0;
            ch->field_12 = 0;
            *(int*)&ch->pad14[4] = 0;
            ch++;
        }
        gMusicChannelCounterA = 1;
        gMusicChannelCounterB = 1;
        gAudioPendingLoadFlags |= 0x800;
        saved = testAndSet_onlyUseHeap3(0);
        gMidiWadFileData = loadFileByPathAsync(sMidiWadPath, &gMidiWadLoadedSize, 0,
                                               (void (*)(void*))MIDIWADLoadedCallback);
        testAndSet_onlyUseHeap3(saved);
    }
    if (gAudioCompletedLoadFlags & 0x800)
    {
        size = gMidiWadLoadedSize;
        if ((int)size & 0x1f)
        {
            size = (size | 0x1f) + 1;
        }
        gMidiWadPayloadStart = (u8*)gMidiWadFileData + 0x1a0;
        gMidiWadPayloadSize = size - 0x1a0;
        gMidiWadArenaSize = 0x1000000 - gMidiWadPayloadSize;
        arenaOffset = gMidiWadArenaSize;
        for (track = 0; track <= 0x63; track++)
        {
            found = NULL;
            for (j = 0, table = (MusicTrackSlot*)sMusicTrackTable; j < 0x64; table++, j++)
            {
                if (track == table->id)
                {
                    found = (MusicTrackSlot*)sMusicTrackTable + j;
                    break;
                }
            }
            if (found != NULL)
            {
                found->offset = arenaOffset;
                found->size = ((int*)gMidiWadFileData)[track];
            }
            {
                u32 size2 = found->size;
                if (size2 & 0x1f)
                {
                    size2 = (size2 | 0x1f) + 1;
                }
                arenaOffset += size2;
            }
        }
        fn_80008F38(gMidiWadPayloadStart, gMidiWadArenaSize, gMidiWadPayloadSize);
        saved = mmSetFreeDelay(0);
        mm_free(gMidiWadFileData);
        mmSetFreeDelay(saved);
        return 1;
    }
    return 0;
}
#pragma opt_strength_reduction reset

void poolDataMLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sPoolDataMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x8LL;
        gAudioCompletedLoadFlags |= 0x8;
    }
}

void poolDataSLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sPoolDataSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x80LL;
        gAudioCompletedLoadFlags |= 0x80;
    }
}

void projectDataMLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sProjectDataMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x10LL;
        gAudioCompletedLoadFlags |= 0x10;
    }
}

void projectDataSLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sProjectDataSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x100LL;
        gAudioCompletedLoadFlags |= 0x100;
    }
}

void sampleBufferMLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSampleBufferMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x40LL;
        gAudioCompletedLoadFlags |= 0x40;
    }
}

void sampleBufferSLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSampleBufferSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x400LL;
        gAudioCompletedLoadFlags |= 0x400;
    }
}

void sampleDirectoryMLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSampleDirectoryMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x20LL;
        gAudioCompletedLoadFlags |= 0x20;
    }
}

void sampleDirectorySLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSampleDirectorySLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x200LL;
        gAudioCompletedLoadFlags |= 0x200;
    }
}

void sfxTriggersLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sSfxTriggersLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x2LL;
        gAudioCompletedLoadFlags |= 0x2;
    }
}

void musicTriggersLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sMusicTriggersLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x1LL;
        gAudioCompletedLoadFlags |= 0x1;
    }
}

void streamsLoadedCallback(int status, void* fileInfo)
{
    u32 saved;
    if (status < 0)
    {
        OSReport(sStreamsLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    }
    else
    {
        StreamEntry* s;
        int count;
        int i;
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        *(s32*)&gAudioPendingLoadFlags &= ~(u64)0x4;
        gAudioCompletedLoadFlags |= 0x4;
        s = gStreamsData;
        count = gStreamsCount;
        for (i = count; i != 0; i--)
        {
            s->flag = 0;
            s++;
        }
    }
}

void fn_80008F38(void* addr, u32 dest, u32 size)
{
    int idx;
    TextCallbackEntry* entry;
    idx = gAudioArqRequestIndex;
    gAudioArqRequestIndex = idx + 1;
    entry = &gAudioArqRequests[idx];
    if (idx + 1 >= 0x10)
    {
        gAudioArqRequestIndex = 0;
    }
    if ((size & 0x1f) != 0)
    {
        size = (size | 0x1f) + 1;
    }
    DCFlushRange(addr, size);
    gAudioArqRequestDone = 0;
    ARQPostRequest(entry, 0x64, 0, 1, (u32)addr, dest, size, (void (*)(void*))fn_80009008);
    while (gAudioArqRequestDone == 0)
    {
    }
}

#pragma dont_inline on
void audioAllocFn_80008df4(void* source, u32 size, void** outBuf, u32 cb, u32 p5, u32 p6, u32 p7)
{
    int idx;
    void* buf;
    TextCallbackEntry* entry;
    idx = gAudioArqRequestIndex;
    gAudioArqRequestIndex = idx + 1;
    entry = &gAudioArqRequests[idx];
    if (idx + 1 >= 0x10)
    {
        gAudioArqRequestIndex = 0;
    }
    if ((size & 0x1f) != 0)
    {
        size = (size | 0x1f) + 1;
    }
    buf = mmAlloc(size, 0, NULL);
    *outBuf = buf;
    entry->fn = (void (*)(int, int, int))cb;
    entry->a = p5;
    entry->b = p6;
    entry->c = p7;
    DCFlushRange(buf, size);
    gAudioArqRequestDone = 0;
    ARQPostRequest(entry, 0x64, 1, 1, (u32)source, (u32)buf, size, (void (*)(void*))fn_80008EDC);
}
#pragma dont_inline reset

int Sfx_ResolveObjectSfxId(int* outChannel, u16* sfxId)
{
    switch (*sfxId)
    {
    case 0x170:
    case 0xca:
    case 0x109:
        *sfxId = 0x409;
    case 0x409:
        *outChannel = 0;
        break;
    case 0x7e:
    case 0x487:
        *outChannel = 0;
        break;
    case 0x420:
        Music_Trigger(0xe7, 0);
        Music_Trigger(0xe7, 1);
        return 0;
    case 0x38c:
        return !(gAudioActiveChannelMask & 4);
    case 0x0:
        return 0;
    }
    return 1;
}

u32 Sfx_PlayFromObjectLimited(u32 obj, int sfxId, int limit)
{
    SfxObjectChannel* ch = Sfx_FindObjectChannel(0, 0, sfxId, 3);
    if (ch != NULL && (int)gSfxObjectChannelMatchCount > limit)
    {
        sndFXKeyOff(*(s32*)ch);
        *(s32*)ch = -1;
    }
    if ((int)gSfxObjectChannelMatchCount < limit)
    {
        extern void Sfx_PlayFromObjectEx(u32 obj, f32* pos, u32 channel, int sfxId);
        Sfx_PlayFromObjectEx(obj, NULL, 0, sfxId);
    }
    return gSfxObjectChannelMatchCount;
}

int AudioStream_Play(int id, void (*preparedCallback)(void))
{
    extern char sAdpExtension;
    char path[64];
    u8 vol;
    u8* dvd = (u8*)(int)gAudioStreamDvdBlockCurrent;
    int* fadeTbl = gAudioStreamFadeTable;
    StreamEntry* s = gStreamsData;
    int count = gStreamsCount;
    int slot = -1;
    int i;
    u8 stopped;

    if (id == 1228)
    {
        return 0;
    }
    if (id == 1318)
    {
        Music_Trigger(0xA8, 0);
        Music_Trigger(0xF4, 1);
    }
    if ((int)audioFlagFn_8000a188(8) != 0)
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

    if (concatThreeStrings(path, (void*)0x40, (char*)fadeTbl + 0x3C, s->name, &sAdpExtension) == 0)
    {
        goto ret0;
    }
    if (DVDOpen(path, dvd + 0x90) == 0)
    {
        return 0;
    }

    if (gAudioStreamCurrentId != 0)
    {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync((u8*)(int)gAudioStreamDvdBlockCurrent, AudioStream_CancelCallback) == 0)
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

    gAudioStreamEndPos = (f32)(u32)
    s->lengthRaw / lbl_803DE5D4;
    if (lbl_803DE5D0 == gAudioStreamEndPos)
    {
        gAudioStreamEndPos = gAudioStreamEndPosInfinite;
    }

    gAudioStreamMusicFadeFlagA = fadeTbl[(s->fadeBits >> 6) & 3] == 0 ? 0 : 1;
    gAudioStreamMusicFadeFlagB = fadeTbl[(s->fadeBits >> 4) & 3] == 0 ? 0 : 1;
    if (((u32)s->fadeBits >> 2) & 3)
    {
        Sfx_StopAllObjectSounds();
    }
    gAudioActiveChannelMask = (((u32)s->volBits >> 7) & 1) ? 4 : 0;

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

    vol = (((s->volBits & 0x7F) + 1) * gAudioStreamDefaultVolume) >> 7;
    gAudioStreamVolumeLeft = vol;
    gAudioStreamVolumeRight = vol;
    AISetStreamVolLeft(vol);
    AISetStreamVolRight(vol);
    gAudioStreamPreparedCallback = preparedCallback;
    gAudioStreamPreparingId = slot;
    gAudioStreamDvdState = 1;
    DVDPrepareStreamAsync(dvd + 0x90, 0, 0, AudioStream_PrepareCallback);
    DVDStopStreamAtEndAsync(dvd + 0x60, 0);
    return 1;
ret0:
    return 0;
}

static inline MusicChannel* Music_FindActiveChannelForTrack(int track)
{
    int i;
    MusicChannel* ch = (MusicChannel*)(int)gMusicChannels;
    for (i = 15; i >= 0; i--)
    {
        if ((int)ch->field_0 == track)
        {
            if (ch->status == 0)
            {
            }
            else if (ch->status == 2)
            {
            }
            else
            {
                switch (ch->status)
                {
                case 5:
                    break;
                default:
                    return ch;
                }
            }
        }
        ch++;
    }
    return NULL;
}

static inline MusicTrigger* Music_FindTriggerById(int id)
{
    int i = gMusicTriggersCount;
    MusicTrigger* trigger = gMusicTriggersData;
    while (i != 0)
    {
        if ((int)trigger->id == id)
        {
            return trigger;
        }
        trigger++;
        i--;
    }
    return NULL;
}

void Music_Trigger(int id, int arg)
{
    MusicTrigger* trigger;
    MusicChannel* channel;
    int i;
    int track;

    if (arg != 1 && arg != 0)
    {
        return;
    }
    trigger = Music_FindTriggerById(id);
    if (trigger == NULL)
    {
        return;
    }
    if (id == 0xeb && arg == 1)
    {
        MusicChannel* ch = Music_FindActiveChannelForTrack(0x5e);
        if (ch != NULL || GameBit_Get(0xa7f) != 0u)
        {
            return;
        }
    }
    track = trigger->track;
    channel = Music_FindActiveChannelForTrack(track);
    if (arg == 1)
    {
        if (channel == NULL)
        {
            Music_LoadChannelForTrigger(trigger);
            return;
        }
        if (channel->status != 1)
        {
            return;
        }
        sndSeqVolume((u8) * (u16*)&channel->pad14[0], *(u16*)trigger->pad, channel->seqHandle, 0);
    }
    else if (channel != NULL)
    {
        int st;
        i = *(u16*)trigger->pad;
        st = channel->status;
        if (st == 2)
        {
            return;
        }
        if (st == 4 || st == 5)
        {
            channel->status = 5;
            return;
        }
        sndSeqVolume(0, (u16)(i < 0x1f4 ? 0x1f4 : i), channel->seqHandle, 1);
        channel->status = 2;
    }
}

static void Music_FreeChannel(MusicChannel* ch)
{
    sndSeqStop(ch->seqHandle);
    mm_free(ch->bankData);
    ch->field_0 = -1;
    ch->seqHandle = -1;
    ch->bankData = NULL;
    ch->voiceId = 0xff;
    ch->status = 0;
    ch->field_12 = 0;
    ch->field_20 = lbl_803DE560;
}

void streamFn_8000a380(int mask, int mode, int time)
{
    MusicChannel* ch = (MusicChannel*)(int)gMusicChannels;
    int i = 15;
    do
    {
        if (ch->status != 0 && ((ch->pad11 + 1) & mask) != 0)
        {
            switch (mode)
            {
            case 1:
                if (audioIsResetting() == 0)
                {
                    if (ch->status != 2)
                    {
                        if (ch->status == 4 || ch->status == 5)
                        {
                            ch->status = 5;
                        }
                        else
                        {
                            sndSeqVolume(0, 250, ch->seqHandle, 1);
                            ch->status = 2;
                        }
                    }
                }
                else if (ch->status == 4 || ch->status == 5)
                {
                    ch->status = 5;
                }
                else
                {
                    Music_FreeChannel(ch);
                }
                break;
            case 2:
                if (ch->status != 2)
                {
                    if (ch->status == 4 || ch->status == 5)
                    {
                        ch->status = 5;
                    }
                    else
                    {
                        sndSeqVolume(0, (u16)(time < 500 ? 500 : time), ch->seqHandle, 1);
                        ch->status = 2;
                    }
                }
                break;
            }
        }
        ch++;
    }
    while (i-- != 0);
}

static int Music_IsTriggerExcluded(int id)
{
    switch (id)
    {
    case 0x2b:
    case 0xbd:
    case 0xeb:
        return 1;
    }
    return 0;
}

void Music_Update(void)
{
    extern void sndSeqVolume(u8 volume, u16 time, u32 handle, u8 mode);
    MusicChannel* ch;
    int i;
    int lowPriority = 0x7fff;
    u32 bestActive18 = 0;
    u32 bestLow18 = 0;
    int activeVol = 0x1f4;
    int lowVol = 0x1f4;
    int s2VolA = 0x1f4;
    int s2VolB = 0x1f4;
    int found20 = 0;
    int found19 = 0;
    u32 fadeB = AudioStream_GetMusicFadeFlagB();
    u32 fadeA = AudioStream_GetMusicFadeFlagA();

    gMusicActivePriority = 0x7fff;

    ch = gMusicChannels;
    i = 0xf;
    do
    {
        int status = ch->status;
        if (status != 0 && status != 4)
        {
            if (gSynthVoices[ch->voiceId].state == 0)
            {
                if (status == 4 || status == 5)
                {
                    ch->status = 5;
                }
                else
                {
                    Music_FreeChannel(ch);
                }
            }
        }
        switch (ch->status)
        {
        case 1:
        case 3:
        case 4:
            if (!Music_IsTriggerExcluded((*(MusicTrigger**)&ch->pad14[8])->id))
            {
                if (ch->pad11 != 0)
                {
                    gMusicActivePriority = ch->field_12 < gMusicActivePriority
                                               ? ch->field_12
                                               : gMusicActivePriority;
                }
                else
                {
                    lowPriority =
                        ch->field_12 < lowPriority ? ch->field_12 : lowPriority;
                }
            }
            break;
        case 2:
            ch->field_20 += timeDelta / gAudioFramesPerSecond;
            if (ch->field_20 > lbl_803DE568)
            {
                if (ch->status == 4 || ch->status == 5)
                {
                    ch->status = 5;
                }
                else
                {
                    Music_FreeChannel(ch);
                }
            }
            break;
        }
        ch++;
    }
    while (i-- != 0);

    ch = gMusicChannels;
    for (i = 0; i < 16; i++)
    {
        switch (ch->status)
        {
        case 1:
        case 3:
        case 4:
            if (!Music_IsTriggerExcluded((*(MusicTrigger**)&ch->pad14[8])->id))
            {
                if (ch->pad11 != 0)
                {
                    if (ch->field_12 == gMusicActivePriority &&
                        *(u32*)&ch->pad14[4] > bestActive18)
                    {
                        bestActive18 = *(u32*)&ch->pad14[4];
                        activeVol = *(u16*)(*(MusicTrigger**)&ch->pad14[8])->pad;
                    }
                }
                else
                {
                    if (ch->field_12 == lowPriority &&
                        *(u32*)&ch->pad14[4] > bestLow18)
                    {
                        bestLow18 = *(u32*)&ch->pad14[4];
                        lowVol = *(u16*)(*(MusicTrigger**)&ch->pad14[8])->pad;
                        if (ch->status != 3)
                        {
                            found20 = 1;
                        }
                    }
                }
            }
            break;
        case 2:
            if (ch->pad11 != 0)
            {
                s2VolA = s2VolA > *(u16*)(*(MusicTrigger**)&ch->pad14[8])->pad
                             ? s2VolA
                             : *(u16*)(*(MusicTrigger**)&ch->pad14[8])->pad;
            }
            else
            {
                s2VolB = s2VolB > *(u16*)(*(MusicTrigger**)&ch->pad14[8])->pad
                             ? s2VolB
                             : *(u16*)(*(MusicTrigger**)&ch->pad14[8])->pad;
                found19 = 1;
            }
            break;
        }
        ch++;
    }

    if (found20)
    {
        activeVol = lowVol;
    }
    if (found19)
    {
        s2VolA = s2VolB;
    }
    if ((int)fadeB != 0)
    {
        if (activeVol >= 0x1f4)
        {
            activeVol = 0x1f4;
        }
    }
    if ((int)fadeA != 0)
    {
        if (lowVol >= 0x1f4)
        {
            lowVol = 0x1f4;
        }
    }

    ch = gMusicChannels;
    i = 0xf;
    do
    {
        int st = ch->status;
        switch (st)
        {
        case 1:
        case 3:
            if (ch->pad11 != 0)
            {
                if (ch->field_12 == gMusicActivePriority &&
                    *(u32*)&ch->pad14[4] < bestActive18)
                {
                    if (st != 2)
                    {
                        if (st == 4 || st == 5)
                        {
                            ch->status = 5;
                        }
                        else
                        {
                            sndSeqVolume(0, (u16)(activeVol < 0x1f4 ? 0x1f4 : activeVol),
                                         ch->seqHandle, 1);
                            ch->status = 2;
                        }
                    }
                }
                else if (ch->field_12 > gMusicActivePriority ||
                    ch->field_12 > lowPriority || (int)fadeB != 0)
                {
                    if (st != 3)
                    {
                        sndSeqVolume(0, (u16)(activeVol < 0x1f4 ? 0x1f4 : activeVol),
                                     ch->seqHandle, (u8)(ch->pad11 != 0 ? 0 : 2));
                        ch->status = 3;
                    }
                }
                else
                {
                    if (st != 1)
                    {
                        sndSeqMute(ch->seqHandle, -1, -1);
                        sndSeqContinue(ch->seqHandle);
                        sndSeqVolume((u8) * (u16*)&ch->pad14[0],
                                     (u16)(s2VolA < 0x1f4 ? 0x1f4 : s2VolA),
                                     ch->seqHandle, 0);
                        ch->status = 1;
                    }
                }
            }
            else
            {
                if (ch->field_12 == lowPriority &&
                    *(u32*)&ch->pad14[4] < bestLow18)
                {
                    if (st != 2)
                    {
                        if (st == 4 || st == 5)
                        {
                            ch->status = 5;
                        }
                        else
                        {
                            sndSeqVolume(0, (u16)(lowVol < 0x1f4 ? 0x1f4 : lowVol),
                                         ch->seqHandle, 1);
                            ch->status = 2;
                        }
                    }
                }
                else if (ch->field_12 > lowPriority ||
                    ch->field_12 > gMusicActivePriority || (int)fadeA != 0)
                {
                    if (st != 3)
                    {
                        sndSeqVolume(0, (u16)(lowVol < 0x1f4 ? 0x1f4 : lowVol),
                                     ch->seqHandle, (u8)(ch->pad11 != 0 ? 0 : 2));
                        ch->status = 3;
                    }
                }
                else
                {
                    if (st != 1)
                    {
                        sndSeqMute(ch->seqHandle, -1, -1);
                        sndSeqContinue(ch->seqHandle);
                        sndSeqVolume((u8) * (u16*)&ch->pad14[0],
                                     (u16)(s2VolB < 0x1f4 ? 0x1f4 : s2VolB),
                                     ch->seqHandle, 0);
                        ch->status = 1;
                    }
                }
            }
            break;
        }
        ch++;
    }
    while (i-- != 0);
}

static inline MusicTrackSlot* Music_FindTrackSlot(int track)
{
    MusicTrackSlot* slot = (MusicTrackSlot*)sMusicTrackTable;
    int i;
    for (i = 99; i >= 0; i--)
    {
        if (slot->id == track)
        {
            return slot;
        }
        slot++;
    }
    return NULL;
}

static inline MusicChannel* Music_FindFreeChannel(void)
{
    MusicChannel* channel = gMusicChannels;
    int i;
    for (i = 15; i >= 0; i--)
    {
        if (channel->status == 0)
        {
            return channel;
        }
        channel++;
    }
    return NULL;
}

void Music_LoadChannelForTrigger(MusicTrigger* trigger)
{
    MusicTrackSlot* slot;
    MusicChannel* channel;
    int counter;
    int track;

    if (((u32)trigger->pad[0xb] >> 5) & 1)
    {
        if ((int)audioFlagFn_8000a188(2) != 0)
        {
            return;
        }
    }
    if (!(((u32)trigger->pad[0xb] >> 5) & 1))
    {
        if ((int)audioFlagFn_8000a188(1) != 0)
        {
            return;
        }
    }
    track = trigger->track;
    slot = Music_FindTrackSlot(track);
    if (slot == NULL)
    {
        return;
    }
    channel = Music_FindFreeChannel();
    if (channel == NULL)
    {
        return;
    }
    channel->field_0 = trigger->track;
    *(u16*)&channel->pad14[0] = trigger->pad[8];
    channel->pad11 = (trigger->pad[0xb] >> 5) & 1;
    channel->status = 4;
    channel->field_12 = trigger->pad[9];
    if (channel->pad11)
    {
        counter = gMusicChannelCounterA;
        gMusicChannelCounterA = counter + 1;
    }
    else
    {
        counter = gMusicChannelCounterB;
        gMusicChannelCounterB = counter + 1;
    }
    *(int*)&channel->pad14[4] = counter;
    *(MusicTrigger**)&channel->pad14[8] = trigger;
    channel->field_20 = lbl_803DE560;
    audioAllocFn_80008df4((void*)slot->offset, slot->size, &channel->bankData,
                          (u32)Music_ChannelLoadedCallback, (u32)slot, (u32)channel, (u32)trigger);
}

void Music_PlayTrackByIndex(int index)
{
    MusicTrigger* trigger = Music_FindTriggerById(0xec);
    streamFn_8000a380(3, 1, 0);
    trigger->track = *(s16*)((u8*)sMusicTrackTable + (index << 4));
    Music_Trigger(0xec, 1);
}

void audioSetSoundMode(int mode, u8 forceFlag)
{
    if (forceFlag == 0)
    {
        if (OSGetSoundMode() != 1)
        {
            return;
        }
    }
    if ((u8)mode != gAudioSoundMode)
    {
        switch ((u8)mode)
        {
        case 0:
            sndOutputMode(1);
            break;
        case 1:
            sndOutputMode(2);
            break;
        case 2:
            sndOutputMode(0);
            break;
        case 3:
            sndOutputMode(1);
            break;
        }
    }
    if ((((u8)mode == 2) && (gAudioSoundMode != 2)) || (((u8)mode != 2) && (gAudioSoundMode == 2)))
    {
        if ((u8)mode == 2)
        {
            OSSetSoundMode(0);
        }
        else
        {
            OSSetSoundMode(1);
        }
    }
    gAudioSoundMode = mode;
}

#pragma dont_inline on
void audioLoadTriggerData(void)
{
    char* base = sSampleBufferSLoadedCallbackLoadError;
    int info;
    int delay;
    if (gMusicTriggersData != NULL)
    {
        delay = mmSetFreeDelay(0);
        mm_free(gMusicTriggersData);
        mm_free(gSfxTriggersData);
        mm_free(gStreamsData);
        mmSetFreeDelay(delay);
    }
    gAudioPendingLoadFlags |= 0x1;
    gMusicTriggersData = loadFileByPathAsync(base + 0x1b4, &info, 1, (void (*)(void*))musicTriggersLoadedCallback);
    gMusicTriggersCount = (u32)info >> 4;
    gAudioPendingLoadFlags |= 0x2;
    gSfxTriggersData = loadFileByPathAsync(base + 0x1cc, &info, 1, (void (*)(void*))sfxTriggersLoadedCallback);
    gSfxTriggersCount = (u32)info >> 5;
    gAudioPendingLoadFlags |= 0x4;
    gStreamsData = loadFileByPathAsync(base + 0x1e0, &info, 1, (void (*)(void*))streamsLoadedCallback);
    gStreamsCount = info / sizeof(StreamEntry);
}
#pragma dont_inline reset

int audioInit(void)
{
    char* base = sSampleBufferSLoadedCallbackLoadError;
    int hooks[2];
    int reverbWork;
    int delay;
    int v;

    hooks[0] = gAudioMemAllocHook;
    hooks[1] = gAudioMemFreeHook;
    if (!gAudioInitStarted)
    {
        gAudioInitStarted = 1;
        gAudioPendingLoadFlags = 0;
        gAudioCompletedLoadFlags = 0;
        testAndSet_onlyUseHeap3(1);
        if (gAudioHardwareInitialized)
        {
            return 1;
        }
        gAudioHardwareInitialized = 1;
        ARInit(gAudioAramBlock, 0xa);
        ARQInit();
        AIInit(0);
        AISetDSPSampleRate(0);
        sndSetHooks(hooks);
        sndInit(0x30, 0x30, 0x18, 1, 1, 0x1000000);
        sndSetMaxVoices(0x30, 0x18);
        if (OSGetSoundMode() == 0)
        {
            gAudioSoundMode = 2;
            sndOutputMode(0);
        }
        else
        {
            gAudioSoundMode = 0;
            sndOutputMode(1);
        }
        gAudioReverbSettings[0x13c] = 0;
        *(f32*)&gAudioReverbSettings[0x148] = lbl_803DE550;
        *(f32*)&gAudioReverbSettings[0x150] = lbl_803DE554;
        *(f32*)&gAudioReverbSettings[0x14c] = lbl_803DE558;
        *(f32*)&gAudioReverbSettings[0x140] = lbl_803DE558;
        *(f32*)&gAudioReverbSettings[0x144] = lbl_803DE55C;
        sndAuxCallbackUpdateSettingsReverbSTD(gAudioReverbSettings);
        reverbWork = 0;
        sndSetAuxProcessingCallbacks(0, sndAuxCallbackReverbSTD, gAudioReverbSettings, 0xff, 0, 0, 0,
                                     0xff, reverbWork);
        {
            extern u32 sndIsInstalled(void);
            if (!sndIsInstalled())
            {
                OSReport(base + 0x1f8);
                return 0xff;
            }
        }
        sndVolume(0x7f, 0, 0xff);
        sndMasterVolume(0x7f, 0x64, 1, 1);
        Sfx_InitObjectChannels();
        AudioStream_Init();
        audioLoadTriggerData();
        testAndSet_onlyUseHeap3(1);
        gAudioPendingLoadFlags |= 0x8;
        gAudioStarfoxMPoolDataHandle = loadFileByPathAsync(base + 0x228, NULL, 0,
                                                           (void (*)(void*))poolDataMLoadedCallback);
        gAudioPendingLoadFlags |= 0x10;
        gAudioStarfoxMProjectDataHandle = loadFileByPathAsync(base + 0x23c, NULL, 0,
                                                              (void (*)(void*))projectDataMLoadedCallback);
        gAudioPendingLoadFlags |= 0x20;
        gAudioStarfoxMSampleDirectoryHandle = loadFileByPathAsync(base + 0x250, NULL, 0,
                                                                  (void (*)(void*))sampleDirectoryMLoadedCallback);
        testAndSet_onlyUseHeap3(0);
        gAudioPendingLoadFlags |= 0x40;
        gAudioStarfoxMSampleBufferHandle = loadFileByPathAsync(base + 0x264, NULL, 0,
                                                               (void (*)(void*))sampleBufferMLoadedCallback);
        if (gAudioStarfoxMPoolDataHandle == NULL || gAudioStarfoxMProjectDataHandle == NULL ||
            gAudioStarfoxMSampleDirectoryHandle == NULL || gAudioStarfoxMSampleBufferHandle == NULL)
        {
            return 0xff;
        }
        testAndSet_onlyUseHeap3(0);
    }
    if (!gAudioMusicGroupReady && (gAudioCompletedLoadFlags & 0x8) && (gAudioCompletedLoadFlags & 0x10) &&
        (gAudioCompletedLoadFlags & 0x8) && (gAudioCompletedLoadFlags & 0x20) &&
        (gAudioCompletedLoadFlags & 0x40))
    {
        sndPushGroup(gAudioStarfoxMProjectDataHandle, 0, gAudioStarfoxMSampleBufferHandle,
                     gAudioStarfoxMSampleDirectoryHandle, gAudioStarfoxMPoolDataHandle);
        delay = mmSetFreeDelay(0);
        mm_free(gAudioStarfoxMSampleBufferHandle);
        mmSetFreeDelay(delay);
        gAudioMusicGroupReady = 1;
        testAndSet_onlyUseHeap3(1);
        gAudioPendingLoadFlags |= 0x80;
        gAudioStarfoxSPoolDataHandle = loadFileByPathAsync(base + 0x278, NULL, 0,
                                                           (void (*)(void*))poolDataSLoadedCallback);
        gAudioPendingLoadFlags |= 0x100;
        gAudioStarfoxSProjectDataHandle = loadFileByPathAsync(base + 0x28c, NULL, 0,
                                                              (void (*)(void*))projectDataSLoadedCallback);
        gAudioPendingLoadFlags |= 0x200;
        gAudioStarfoxSSampleDirectoryHandle = loadFileByPathAsync(base + 0x2a0, NULL, 0,
                                                                  (void (*)(void*))sampleDirectorySLoadedCallback);
        testAndSet_onlyUseHeap3(0);
        gAudioPendingLoadFlags |= 0x400;
        gAudioStarfoxSSampleBufferHandle = loadFileByPathAsync(base + 0x2b4, NULL, 0,
                                                               (void (*)(void*))sampleBufferSLoadedCallback);
        if (gAudioStarfoxSPoolDataHandle == NULL || gAudioStarfoxSProjectDataHandle == NULL ||
            gAudioStarfoxSSampleDirectoryHandle == NULL || gAudioStarfoxSSampleBufferHandle == NULL)
        {
            return 0xff;
        }
    }
    if (!gAudioSfxGroupsReady && (gAudioCompletedLoadFlags & 0x80) && (gAudioCompletedLoadFlags & 0x100) &&
        (gAudioCompletedLoadFlags & 0x80) && (gAudioCompletedLoadFlags & 0x200) &&
        (gAudioCompletedLoadFlags & 0x400))
    {
        for (v = 1; v <= 0x37; v++)
        {
            if (sndPushGroup(gAudioStarfoxSProjectDataHandle, v, gAudioStarfoxSSampleBufferHandle,
                             gAudioStarfoxSSampleDirectoryHandle, gAudioStarfoxSPoolDataHandle) == 0)
            {
                OSReport(base + 0x2c8, v);
            }
        }
        delay = mmSetFreeDelay(0);
        mm_free(gAudioStarfoxSSampleBufferHandle);
        mmSetFreeDelay(delay);
        gAudioSfxGroupsReady = 1;
    }
    if (!gAudioReady && gAudioMusicGroupReady && gAudioSfxGroupsReady)
    {
        extern u8 musicInitMidiWad(void);
        gAudioReady = musicInitMidiWad();
    }
    if (gAudioReady&& gAudioMusicGroupReady && gAudioSfxGroupsReady &&

        (gAudioCompletedLoadFlags & 0x1) && (gAudioCompletedLoadFlags & 0x2) &&
            (gAudioCompletedLoadFlags & 0x4)
    )
    {
        gAudioResetting = 0;
        gAudioManagedChannelMask = 0x1f;
        gAudioActiveChannelMask = 0;
        return 1;
    }
    return 0;
}
