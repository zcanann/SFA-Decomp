#include "ghidra_import.h"
#include "main/engine_shared.h"

#pragma scheduling off
#pragma peephole off
void audioStopByMask(int mask)
{
    if ((mask & 4) != 0) {
        Sfx_StopAllObjectSounds();
    }
    if ((mask & 1) != 0) {
        streamFn_8000a380(1, 1, 0);
    }
    if ((mask & 2) != 0) {
        streamFn_8000a380(2, 1, 0);
    }
    if ((mask & 8) != 0) {
        AudioStream_StopCurrent();
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void audioReset(void)
{
    if (gAudioInitStarted != 0) {
        sndQuit();
    }
    AIReset();
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int audioIsResetting(void)
{
    return gAudioResetting;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void audioStopAll(void)
{
    gAudioResetting = 1;
    Sfx_StopAllObjectSounds();
    streamFn_8000a380(1, 1, 0);
    streamFn_8000a380(2, 1, 0);
    AudioStream_StopCurrent();
    gAudioManagedChannelMask &= ~0xfU;
    gAudioResetting = 1;
    if ((lbl_803DD610 == 2) || (lbl_803DD610 == 3)) {
        Movie_SetVolumeFade(0, 500);
    }
    AudioStream_CancelPrepared();
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void audioUpdate(void)
{
    Music_Update();
    Sfx_UpdateObjectSounds();
    AudioStream_UpdateFadeTimer();
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
u32 audioFlagFn_8000a188(u32 mask)
{
    s32 managed = gAudioManagedChannelMask & mask;
    if (managed == 0) {
        return 1;
    }
    return (gAudioActiveChannelMask & mask) != 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void audioFree(void *ptr)
{
    mm_free(ptr);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void *_audioAlloc(u32 size)
{
    return mmAlloc(size, 0xb, NULL);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Music_ChannelLoadedCallback(MusicBank *bank, MusicChannel *channel, MusicTrigParam *trigger)
{
    MusicSeqStartParams params = lbl_802C1A68;

    if (channel != NULL) {
        if (channel->status == 5) {
            mm_free(channel->bankData);
            channel->field_0 = -1;
            channel->seqHandle = -1;
            channel->bankData = NULL;
            channel->voiceId = 0xff;
            channel->status = 0;
            channel->field_12 = 0;
            channel->field_20 = lbl_803DE560;
        } else {
            int voice;
            int seqHandle;
            if (trigger->field_6 != -1) {
                params.field_c = trigger->field_6;
                params.flags |= 2;
            }
            if (trigger->field_c != -1) {
                voice = trigger->field_c;
            } else {
                voice = 0x7f;
            }
            params.field_10 = 0;
            params.field_e = 0;
            params.flags |= 4;
            seqHandle = fn_8027B9DC(bank->field_2, trigger->field_2, channel->bankData, &params, 0);
            sndSeqVolume(voice, 0x1f4, seqHandle, 0);
            channel->status = 1;
            channel->seqHandle = seqHandle;
            channel->voiceId = synthResolveHandle(seqHandle);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Sfx_ReadTriggerParams(SfxTriggerFull *trigger, u16 *outSfxId, u8 *outVol, f32 *outF6,
                          f32 *outF7, f32 *outF8, int *outI9, int *outI10, int *outI11)
{
    int idx;
    int selector;

    if (trigger == NULL || trigger->f_count == 0) {
        return 0;
    }

    selector = randomGetRange(1, trigger->selectRange);
    if (trigger->id == 0xab) {
        if (trigger->f_curIdx == 0) {
            trigger->f_curIdx = 1;
        } else {
            trigger->f_curIdx = 0;
        }
        idx = trigger->f_curIdx;
    } else {
        idx = 0;
        while (selector > trigger->weights[idx]) {
            selector -= trigger->weights[idx];
            idx++;
        }
        if (trigger->f_curIdx == idx) {
            idx++;
            if (idx >= trigger->f_count) {
                idx = 0;
            }
        }
    }
    trigger->f_curIdx = idx;

    *outSfxId = trigger->sfxIds[idx];
    if (*outSfxId == 0) {
        return 0;
    }

    {
        u8 vr = trigger->volRand;
        if (vr != 0) {
            int hi = trigger->volBase + randomGetRange(0, vr);
            *outVol = hi - randomGetRange(0, vr);
        } else {
            *outVol = trigger->volBase;
        }
    }
    {
        u8 pr = trigger->pitchRand;
        if (pr != 0) {
            int hi = trigger->pitchBase + randomGetRange(0, pr);
            *outF6 = (f32)(hi - randomGetRange(0, pr));
        } else {
            *outF6 = (f32)(u32)trigger->pitchBase;
        }
    }
    *outF7 = (f32)(u32)trigger->field_6;
    *outF8 = (f32)(u32)trigger->field_8;
    *outI9 = (&lbl_803DB248)[trigger->e_tableIdx];
    *outI10 = trigger->e_bit0;
    *outI11 = trigger->e_bit3;
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
SfxTrigger *Sfx_FindTrigger(u16 id)
{
    SfxTrigger *low = (SfxTrigger *)gSfxTriggersData;
    SfxTrigger *high = (SfxTrigger *)gSfxTriggersData + gSfxTriggersCount;
    SfxTriggerCacheEntry *c = &lbl_802C5D78[id & 0xf];

    if (c->key == id) {
        return (SfxTrigger *)gSfxTriggersData + c->index;
    }
    while (low < high) {
        SfxTrigger *mid = low + (high - low) / 2;
        if (mid->id > id) {
            high = mid;
        } else if (mid->id < id) {
            low = mid + 1;
        } else {
            c->key = id;
            c->index = mid - (SfxTrigger *)gSfxTriggersData;
            return mid;
        }
    }
    return NULL;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
SfxObjectChannel *Sfx_AllocObjectChannel(s16 a, int b, f32 pitch, int c, int d)
{
    SfxObjectChannel *ch;
    s32 i;
    u32 handle;

    if (audioFlagFn_8000a188(4)) {
        return 0;
    }

    ch = gSfxObjectChannels;
    for (i = SFX_OBJECT_CHANNEL_COUNT - 1; i >= 0; i--) {
        if (ch->handle == (u32)-1) {
            break;
        }
        ch++;
    }
    if (i < 0) {
        ch = NULL;
    }
    if (ch == NULL) {
        return 0;
    }

    handle = sndFXStartEx(a, b, c, 0);
    if (handle == (u32)-1) {
        ch->handle = (u32)-1;
        return 0;
    }
    if (lbl_803DC838 != 0 && d == 0) {
        sndFXCtrl(handle, 0x5b, 0);
    }

    {
        f32 fz = lbl_803DE570;
        ch->object = 0;
        ch->channelMask = 0;
        ch->paused = 0;
        ch->hasPosition = 0;
        ch->tracksObjectPosition = 0;
        ch->handle = handle;
        ch->x = fz;
        ch->y = fz;
        ch->z = fz;
    }
    *(s16 *)((u8 *)ch + 8) = a;
    ch->volume = 0x64;
    *(f32 *)((u8 *)ch + 0x20) = lbl_803DE590;
    *(f32 *)((u8 *)ch + 0x24) = *(f32 *)((u8 *)&lbl_803DE593 + 1);
    ch->globalCtrlDisabled = (u8)d;

    ch->age = ((u64)gSfxObjectChannelAgeHi << 32) | gSfxObjectChannelAgeLo;
    {
        u64 next = (((u64)gSfxObjectChannelAgeHi << 32) | gSfxObjectChannelAgeLo) + 1;
        gSfxObjectChannelAgeHi = (u32)(next >> 32);
        gSfxObjectChannelAgeLo = (u32)next;
    }
    return ch;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Sfx_RotateVectorByAngles(s16 angX, s16 angY, s16 angZ, f32 *v)
{
    f32 x = v[0];
    f32 y = v[1];
    f32 z = v[2];
    f32 ra = lbl_803DE5AC * (f32)angX / lbl_803DE5B0;
    f32 ca = fn_80293E80(ra);
    f32 rb = lbl_803DE5AC * (f32)angY / lbl_803DE5B0;
    f32 cb = fn_80293E80(rb);
    f32 rc = lbl_803DE5AC * (f32)angZ / lbl_803DE5B0;
    f32 cc = fn_80293E80(rc);
    f32 sa = sin(ra);
    f32 sb = sin(rb);
    f32 sc = sin(rc);
    f32 A = x * sa + z * ca;
    f32 p = z * sa - x * ca;
    f32 B = y * sb - p * cb;
    f32 C = p * sb + y * cb;

    v[0] = A * sc - B * cc;
    v[1] = B * sc + A * cc;
    v[2] = C;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
f32 Sfx_GetListenerRelativeDistance(f32 *soundPos, f32 *outDelta)
{
    f32 v[3];
    f32 t;
    f32 *listener;
    void *player = Obj_GetPlayerObject();
    void *slot = Camera_GetCurrentViewSlot();
    int seqNo = getCurSeqNo();

    if (player != NULL && seqNo == 0) {
        listener = (f32 *)((u8 *)player + 0x18);
    } else {
        if (slot == NULL) {
            return lbl_803DE570;
        }
        if (player != NULL) {
            PSVECSubtract((f32 *)((u8 *)slot + 0x44), (f32 *)((u8 *)player + 0x18), v);
            t = (PSVECMag(v) - lbl_803DE5B4) / lbl_803DE5B8;
            t = (t > lbl_803DE5C8 ? t : lbl_803DE5C8) > lbl_803DE5C0
                    ? lbl_803DE5C0
                    : (t > lbl_803DE5C8 ? t : lbl_803DE5C8);
            PSVECScale(v, v, t);
            PSVECAdd((f32 *)((u8 *)player + 0x18), v, v);
            listener = v;
        } else {
            listener = (f32 *)((u8 *)slot + 0x44);
        }
    }
    PSVECSubtract(listener, soundPos, outDelta);
    return PSVECMag(outDelta);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void AudioStream_StopAll(void)
{
    if (gAudioStreamDvdState != 0) {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(lbl_80336C70, fn_8000D0B4) == 0) {
            OSReport(lbl_802C5DC4);
        }
        gAudioStreamPreparedId = 0;
        gAudioStreamPreparingId = 0;
        gAudioStreamCurrentId = 0;
        gAudioStreamStartWhenPrepared = 0;
        gAudioActiveChannelMask = 0;
        gAudioStreamMusicFadeFlagB = 0;
        gAudioStreamMusicFadeFlagA = 0;
    }

    if (gAudioStreamCurrentId != 0) {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(lbl_80336C40, AudioStream_CancelCallback) == 0) {
            OSReport(lbl_802C5DC4);
            gAudioStreamPlaying = 0;
        }
    } else {
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
u32 AudioStream_GetMusicFadeFlagA(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos) {
        return 0;
    }
    return gAudioStreamMusicFadeFlagA;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
u32 AudioStream_GetMusicFadeFlagB(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos) {
        return 0;
    }
    return gAudioStreamMusicFadeFlagB;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u32 AudioStream_GetCurrentId(void)
{
    return gAudioStreamCurrentId;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u8 AudioStream_IsPreparing(void)
{
    return gAudioStreamDvdState;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void AudioStream_SetVolume(u8 volume)
{
    gAudioStreamVolumeLeft = volume;
    gAudioStreamVolumeRight = volume;
    AISetStreamVolLeft(volume);
    AISetStreamVolRight(volume);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void AudioStream_CancelCallback(s32 result)
{
    if (result == 0) {
        AISetStreamPlayState(0);
    }
    gAudioActiveChannelMask = 0;
    gAudioStreamPlaying = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void AudioStream_StopCurrent(void)
{
    if (gAudioStreamCurrentId != 0) {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(lbl_80336C40, AudioStream_CancelCallback) == 0) {
            OSReport(lbl_802C5DC4);
            gAudioStreamPlaying = 0;
        }
        gAudioStreamPreparedId = 0;
        gAudioStreamPreparingId = 0;
        gAudioStreamCurrentId = 0;
        gAudioStreamStartWhenPrepared = 0;
        gAudioActiveChannelMask = 0;
        gAudioStreamMusicFadeFlagB = 0;
        gAudioStreamMusicFadeFlagA = 0;
    } else {
        gAudioStreamPlaying = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8000D0B4(void)
{
    gAudioStreamDvdState = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void AudioStream_CancelPrepared(void)
{
    AISetStreamVolLeft(0);
    AISetStreamVolRight(0);
    if (DVDCancelStreamAsync(lbl_80336C70, fn_8000D0B4) == 0) {
        OSReport(lbl_802C5DC4);
    }
    gAudioStreamPreparedId = 0;
    gAudioStreamPreparingId = 0;
    gAudioStreamCurrentId = 0;
    gAudioStreamStartWhenPrepared = 0;
    gAudioActiveChannelMask = 0;
    gAudioStreamMusicFadeFlagB = 0;
    gAudioStreamMusicFadeFlagA = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void AudioStream_StartPrepared(void)
{
    if (gAudioStreamPreparingId != 0) {
        gAudioStreamStartWhenPrepared = 1;
    } else if (gAudioStreamPreparedId != 0) {
        if (getGameState() == 1) {
            if (getGameState() == 1) {
                AISetStreamVolLeft(gAudioStreamVolumeLeft);
                AISetStreamVolRight(gAudioStreamVolumeRight);
                AISetStreamPlayState(1);
                gAudioStreamPlaying = 1;
                gAudioStreamPos = lbl_803DE5D0;
                gAudioStreamCurrentId = gAudioStreamPreparedId;
                gAudioStreamPreparedId = 0;
                gAudioStreamPreparingId = 0;
                gAudioStreamStartWhenPrepared = 0;
            } else {
                gAudioStreamPlaying = 0;
            }
        }
    } else if (gAudioStreamCurrentId == 0) {
        gAudioStreamMusicFadeFlagB = 0;
        gAudioStreamMusicFadeFlagA = 0;
        gAudioStreamStartWhenPrepared = 0;
        gAudioActiveChannelMask = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void AudioStream_UpdateFadeTimer(void)
{
    if (gAudioStreamCurrentId != 0) {
        f32 position = gAudioStreamPos;
        gAudioStreamPos = position + (timeDelta / lbl_803DE5E8);
    } else {
        gAudioStreamPos = lbl_803DE5D0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void AudioStream_SetDefaultVolume(u8 volume)
{
    gAudioStreamDefaultVolume = volume;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void AudioStream_PrepareCallback(void)
{
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
            AISetStreamPlayState(1);
            gAudioStreamPlaying = 1;
            gAudioStreamPos = lbl_803DE5D0;
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void AudioStream_PlayAddrCallback(u32 result)
{
    if ((result & 0xff) == 0) {
        gAudioStreamPlaying = 0;
        if (gAudioStreamCurrentId != 0) {
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_ClearLoopedObjectSounds(void)
{
    gSfxLoopedObjectSoundCount = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_UpdateLoopedObjectSounds(void)
{
    SfxLoopedObjectSoundTable *table = &gSfxLoopedObjectSoundFlags;
    u8 *flags = table->flags;
    u16 *ids = table->ids;
    u32 *objects = table->objects;
    s16 i;
    u32 obj;
    u16 sfxId;
    u16 oldCount;
    u16 index;
    u32 removeSound;

    for (i = (s16)(gSfxLoopedObjectSoundCount - 1); i >= 0; i--) {
        removeSound = 0;
        if (((flags[i] & SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE) != 0) &&
            ((flags[i] & SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN) == 0)) {
            removeSound = 1;
        }
        obj = objects[i];
        if (((obj != 0) && ((*(u16 *)(obj + 0xB0) & SFX_LOOPED_OBJECT_STOP_FLAG) != 0)) || removeSound) {
            Sfx_StopFromObject(obj, ids[i]);
            oldCount = gSfxLoopedObjectSoundCount;
            gSfxLoopedObjectSoundCount = (u16)(oldCount - 1);
            index = (u16)i;
            memmove(&objects[index], &objects[index + 1],
                    (((oldCount - 1) - index) * sizeof(u32)) & 0xFFFC);
            memmove(&ids[index], &ids[index + 1],
                    ((gSfxLoopedObjectSoundCount - index) * sizeof(u16)) & 0xFFFE);
            memmove(&flags[index], &flags[index + 1],
                    (gSfxLoopedObjectSoundCount - index) & 0xFFFF);
        } else {
            flags[i] &= ~SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
        }
    }

    for (i = 0; i < gSfxLoopedObjectSoundCount; i++) {
        obj = objects[i];
        sfxId = ids[i];
        if (Sfx_IsPlayingFromObject(obj, sfxId) == 0) {
            Sfx_PlayFromObject(obj, sfxId);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit)
{
    SfxLoopedObjectSoundTable *table = &gSfxLoopedObjectSoundFlags;
    u8 *flags = table->flags;
    u16 *ids = table->ids;
    u32 *objects = table->objects;
    s16 i;
    u16 count = gSfxLoopedObjectSoundCount;
    u16 sameSfxCount = 0;
    u32 found;

    for (i = 0; i < count; i++) {
        if (sfxId == ids[i]) {
            if (limit != 0) {
                sameSfxCount++;
            }
            if (objects[i] == obj) {
                flags[i] |= SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE | SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
                return;
            }
        }
    }

    if (sameSfxCount <= limit) {
        found = 0;
        for (i = 0; i < count; i++) {
            if ((objects[i] == obj) && (sfxId == ids[i])) {
                found = 1;
                break;
            }
        }

        if ((found == 0) && (count != SFX_LOOPED_OBJECT_SOUND_COUNT)) {
            objects[count] = obj;
            ids[count] = sfxId;
            flags[count] = 0;
            gSfxLoopedObjectSoundCount++;
            Sfx_PlayFromObject(obj, sfxId);
        }
    }

    if (count != gSfxLoopedObjectSoundCount) {
        flags[count] |= SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE | SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId)
{
    Sfx_KeepAliveLoopedObjectSoundLimited(obj, sfxId, 0);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_RemoveLoopedObjectSoundForObject(u32 obj)
{
    SfxLoopedObjectSoundTable *table = &gSfxLoopedObjectSoundFlags;
    s16 i;
    u16 oldCount;
    u16 index;

    for (i = (s16)(gSfxLoopedObjectSoundCount - 1); i >= 0; i--) {
        if (table->objects[i] == obj) {
            Sfx_StopFromObject(obj, table->ids[i]);
            oldCount = gSfxLoopedObjectSoundCount;
            gSfxLoopedObjectSoundCount = (u16)(oldCount - 1);
            index = (u16)i;
            memmove(&table->objects[index], &table->objects[index + 1],
                    (((oldCount - 1) - index) * sizeof(u32)) & 0xFFFC);
            memmove(&table->ids[index], &table->ids[index + 1],
                    ((gSfxLoopedObjectSoundCount - index) * sizeof(u16)) & 0xFFFE);
            memmove(&table->flags[index], &table->flags[index + 1],
                    (gSfxLoopedObjectSoundCount - index) & 0xFFFF);
            return;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_RemoveLoopedObjectSound(u32 obj, u32 sfxId)
{
    SfxLoopedObjectSoundTable *table = &gSfxLoopedObjectSoundFlags;
    s16 i;
    u16 oldCount;
    u16 index;

    for (i = (s16)(gSfxLoopedObjectSoundCount - 1); i >= 0; i--) {
        if ((table->objects[i] == obj) && (table->ids[i] == (u16)sfxId)) {
            oldCount = gSfxLoopedObjectSoundCount;
            gSfxLoopedObjectSoundCount = (u16)(oldCount - 1);
            index = (u16)i;
            memmove(&table->objects[index], &table->objects[index + 1],
                    (((oldCount - 1) - index) * sizeof(u32)) & 0xFFFC);
            memmove(&table->ids[index], &table->ids[index + 1],
                    ((gSfxLoopedObjectSoundCount - index) * sizeof(u16)) & 0xFFFE);
            memmove(&table->flags[index], &table->flags[index + 1],
                    (gSfxLoopedObjectSoundCount - index) & 0xFFFF);
            Sfx_StopFromObject(obj, sfxId);
            return;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_AddLoopedObjectSound(u32 obj, u32 sfxId)
{
    SfxLoopedObjectSoundTable *table;
    u32* objectIt;
    u16* idIt;
    s16 i;
    u16 count;
    u32 found = 0;

    table = &gSfxLoopedObjectSoundFlags;
    i = 0;
    objectIt = table->objects;
    idIt = table->ids;
    count = gSfxLoopedObjectSoundCount;
    for (; i < count; i++) {
        if ((*objectIt == obj) && (*idIt == (u16)sfxId)) {
            found = 1;
            break;
        }
        objectIt++;
        idIt++;
    }

    if ((found == 0) && (count != SFX_LOOPED_OBJECT_SOUND_COUNT)) {
        table->objects[count] = obj;
        table->ids[count] = sfxId;
        table->flags[count] = 0;
        gSfxLoopedObjectSoundCount++;
        Sfx_PlayFromObject(obj, sfxId);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int return0x64_8000A378(void) { return 0x64; }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void doNothing_8000CF54(void) {}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
s32 Music_GetActivePriority(void)
{
    return gMusicActivePriority;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
s32 Sfx_IsPlayingFromObjectChannel(u32 obj, u32 channel)
{
    SfxObjectChannel* objectChannel;

    if (((u8)channel == 0) || (obj == 0)) {
        objectChannel = NULL;
    } else {
        objectChannel = Sfx_FindObjectChannel(obj, channel, 0, 0);
    }

    if (objectChannel != NULL) {
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId)
{
    SfxObjectChannel* objectChannel;

    if ((u16)sfxId != 0) {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 0);
    } else {
        objectChannel = NULL;
    }

    if (objectChannel != NULL) {
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Sfx_StopAllObjectSounds(void)
{
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if (objectChannel->handle != (u32)-1) {
            sndFXKeyOff(objectChannel->handle);
            objectChannel->handle = (u32)-1;
        }
        objectChannel++;
    } while (i-- != 0);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void audioFn_8000b694(u32 value)
{
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    lbl_803DC838 = (u8)(value * 5);
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if ((objectChannel->handle != (u32)-1) && (objectChannel->globalCtrlDisabled == 0)) {
            sndFXCtrl(objectChannel->handle, 0x5B, lbl_803DC838);
        }
        objectChannel++;
    } while (i-- != 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_SetObjectSoundsPaused(s32 paused)
{
    u8 pausedByte;
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    pausedByte = paused;

    do {
        if (objectChannel->handle != (u32)-1) {
            if (paused != 0) {
                sndFXCtrl(objectChannel->handle, 7, 0);
            } else if (objectChannel->paused != 0) {
                sndFXCtrl(objectChannel->handle, 7, objectChannel->volume);
            }
            objectChannel->paused = pausedByte;
        }
        objectChannel++;
    } while (i-- != 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_StopObjectChannel(u32 obj, u32 channel)
{
    SfxObjectChannel* objectChannel;

    if (((u8)channel == 0) || (obj == 0)) {
        objectChannel = NULL;
    } else {
        objectChannel = Sfx_FindObjectChannel(obj, channel, 0, 0);
    }

    if (objectChannel != NULL) {
        sndFXKeyOff(objectChannel->handle);
        objectChannel->handle = (u32)-1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Sfx_StopFromObject(u32 obj, u32 sfxId)
{
    SfxObjectChannel* objectChannel;

    if ((u16)sfxId != 0) {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 0);
    } else {
        objectChannel = NULL;
    }

    if (objectChannel != NULL) {
        sndFXKeyOff(objectChannel->handle);
        objectChannel->handle = (u32)-1;
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_SetObjectChannelVolume(f32 volumeScale, u32 obj, u32 channel, u8 volume)
{
    u8 volumeByte;
    SfxObjectChannel* objectChannel;

    volumeByte = volume;
    if (((u8)channel == 0) || (obj == 0)) {
        objectChannel = NULL;
    } else {
        objectChannel = Sfx_FindObjectChannel(obj, channel, 0, 2);
    }

    if (objectChannel != NULL) {
        if ((u8)volumeByte != 0xFE) {
            u32 ctrlVolume;

            if ((u8)volumeByte == 0xFF) {
                volumeByte = 100;
            }
            objectChannel->volume = volumeByte;
            if (objectChannel->hasPosition != 0) {
                Sfx_UpdateObjectChannel3D(objectChannel);
            } else {
                if (objectChannel->paused != 0) {
                    ctrlVolume = 0;
                } else {
                    ctrlVolume = volumeByte;
                }
                sndFXCtrl(objectChannel->handle, 7, (u8)ctrlVolume);
            }
        }

        if (volumeScale < lbl_803DE570) {
            volumeScale = lbl_803DE570;
        }
        if (volumeScale > lbl_803DE574) {
            volumeScale = lbl_803DE574;
        }
        sndFXCtrl14(objectChannel->handle, 0x80, (s32)(lbl_803DE578 * volumeScale));
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Sfx_SetObjectSfxVolume(f32 volumeScale, u32 obj, u32 sfxId, u8 volume)
{
    u8 volumeByte;
    SfxObjectChannel* objectChannel;

    volumeByte = volume;
    if ((u16)sfxId != 0) {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 2);
    } else {
        objectChannel = NULL;
    }

    if (objectChannel != NULL) {
        if ((u8)volumeByte != 0xFE) {
            u32 ctrlVolume;

            if ((u8)volumeByte == 0xFF) {
                volumeByte = 100;
            }
            objectChannel->volume = volumeByte;
            if (objectChannel->hasPosition != 0) {
                Sfx_UpdateObjectChannel3D(objectChannel);
            } else {
                if (objectChannel->paused != 0) {
                    ctrlVolume = 0;
                } else {
                    ctrlVolume = volumeByte;
                }
                sndFXCtrl(objectChannel->handle, 7, (u8)ctrlVolume);
            }
        }

        if (volumeScale < lbl_803DE570) {
            volumeScale = lbl_803DE570;
        }
        if (volumeScale > lbl_803DE574) {
            volumeScale = lbl_803DE574;
        }
        sndFXCtrl14(objectChannel->handle, 0x80, (s32)(lbl_803DE578 * volumeScale));
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_UpdateObjectChannel3D(SfxObjectChannel *objectChannel)
{
    void *slot;
    f32 volf;
    int baseVol;
    f32 near;
    f32 far;
    f32 dist;
    f32 delta[3];

    slot = Camera_GetCurrentViewSlot();
    if (slot == NULL) {
        return;
    }
    if (objectChannel == NULL) {
        return;
    }
    if (!objectChannel->hasPosition) {
        return;
    }
    volf = (f32)(u32)objectChannel->volume;
    baseVol = (int)volf;
    near = *(f32 *)((u8 *)objectChannel + 0x20);
    far = *(f32 *)((u8 *)objectChannel + 0x24);
    dist = Sfx_GetListenerRelativeDistance(&objectChannel->x, delta);
    if (dist > lbl_803DE598 * far) {
        sndFXKeyOff(objectChannel->handle);
        objectChannel->handle = (u32)-1;
        return;
    }
    Sfx_RotateVectorByAngles(0, 0, -*(s16 *)((u8 *)slot + 0x54), delta);
    Sfx_RotateVectorByAngles(*(s16 *)slot, 0, 0, delta);
    Sfx_RotateVectorByAngles(0, -*(s16 *)((u8 *)slot + 0x52), 0, delta);
    if (dist > lbl_803DE59C) {
        int level;
        f32 scale;
        int pan;
        int fx;

        if (dist < near) {
            level = (int)volf;
        } else if (dist > far) {
            level = 1;
        } else {
            level = (int)(volf * (lbl_803DE574 - (dist - near) / (far - near)));
            if (level < 1) {
                level = 1;
            } else if ((f32)level > volf) {
                level = (int)volf;
            }
        }
        scale = lbl_803DE5A0 / dist;
        delta[0] = delta[0] * scale;
        delta[1] = delta[1] * scale;
        delta[2] = delta[2] * scale;
        pan = (int)(lbl_803DE5A8 * delta[0] + lbl_803DE5A4);
        if (pan > 0x7f) {
            pan = 0x7f;
        } else if (pan < 0) {
            pan = 0;
        }
        fx = (int)(lbl_803DE5A8 * delta[2] + lbl_803DE5A4);
        if (fx > 0x7f) {
            fx = 0x7f;
        } else if (fx < 0) {
            fx = 0;
        }
        sndFXCtrl(objectChannel->handle, 0xa, (u8)pan);
        sndFXCtrl(objectChannel->handle, 0x83, (u8)fx);
        if (objectChannel->paused) {
            level = 0;
        }
        sndFXCtrl(objectChannel->handle, 7, (u8)level);
    } else {
        int v;
        if (objectChannel->paused) {
            v = 0;
        } else {
            v = baseVol;
        }
        sndFXCtrl(objectChannel->handle, 7, (u8)v);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_PlayFromObjectEx(u32 obj, f32 *pos, u32 channel, u16 sfxId)
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
    SfxObjectChannel *found;
    SfxObjectChannel *ch;
    int tracksObj;

    tracksObj = 0;
    if (!Sfx_ResolveObjectSfxId((int *)&obj, &sfxId)) {
        return;
    }
    if (!Sfx_ReadTriggerParams((SfxTriggerFull *)Sfx_FindTrigger(sfxId), &outSfxId,
                               &vol, &pitch, &f7, &f8, &i9, &i10, &i11)) {
        return;
    }
    if (obj != 0 && pos == NULL) {
        pos = (f32 *)(obj + 0x18);
        tracksObj = 1;
    }
    if (pos != NULL) {
        f32 maxDist = f8;
        if (!(Sfx_GetListenerRelativeDistance(pos, delta) <= maxDist)) {
            return;
        }
    }
    if ((u8)channel != 0) {
        i9 = (u8)channel;
    }
    if (obj != 0 && i9 != 0) {
        if ((u8)i9 != 0 && obj != 0) {
            found = Sfx_FindObjectChannel(obj, (u8)i9, 0, 0);
        } else {
            found = NULL;
        }
        if (found != NULL) {
            if (i10 == 0) {
                return;
            }
            sndFXKeyOff(found->handle);
            found->handle = (u32)-1;
        }
    } else {
        if (sfxId != 0) {
            found = Sfx_FindObjectChannel(obj, 0, sfxId, 1);
        } else {
            found = NULL;
        }
        if (found != NULL) {
            if (i10 != 0 || gSfxObjectChannelMatchCount == 3) {
                sndFXKeyOff(found->handle);
                found->handle = (u32)-1;
            }
        }
    }
    ch = Sfx_AllocObjectChannel(outSfxId, vol, pitch, 0x40, i11);
    if (ch == NULL) {
        return;
    }
    ch->sfxId = sfxId;
    ch->channelMask = (u16)i9;
    ch->object = obj;
    if (pos != NULL) {
        *(f32 *)((u8 *)ch + 0x20) = f7;
        *(f32 *)((u8 *)ch + 0x24) = f8;
        ch->hasPosition = 1;
        {
            int t = 0;
            if (tracksObj != 0 && i9 != 0) {
                t = 1;
            }
            ch->tracksObjectPosition = (u8)t;
        }
        ch->x = pos[0];
        ch->y = pos[1];
        ch->z = pos[2];
        Sfx_UpdateObjectChannel3D(ch);
    } else {
        ch->volume = 0x7f;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_PlayFromObjectChannel(u32 obj, u32 channel, u32 sfxId)
{
    Sfx_PlayFromObjectEx(obj, NULL, channel, sfxId);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u32 obj, u32 sfxId)
{
    f32 pos[3];

    pos[0] = x;
    pos[1] = y;
    pos[2] = z;
    Sfx_PlayFromObjectEx(obj, pos, 0, sfxId);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Sfx_PlayFromObject(u32 obj, u32 sfxId)
{
    Sfx_PlayFromObjectEx(obj, NULL, 0, sfxId);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Sfx_UpdateObjectSounds(void)
{
    SfxObjectChannel* objectChannel;
    s32 i;
    u32 globalCtrl;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if ((objectChannel->handle != (u32)-1) && ((u32)sndFXCheck(objectChannel->handle) == (u32)-1)) {
            objectChannel->handle = (u32)-1;
        }
        objectChannel++;
    } while (i-- != 0);

    if (GameBit_Get(0xCBB) != 0) {
        globalCtrl = 0xE;
    } else if (GameBit_Get(0xEFA) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xEFB) != 0) {
        globalCtrl = 0xD;
    } else if (GameBit_Get(0xEFD) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xA7F) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xEFC) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xEFE) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xDCF) != 0) {
        globalCtrl = 0xB;
    } else if (Music_GetActivePriority() <= 0x28) {
        globalCtrl = 0xC;
    } else {
        globalCtrl = 0;
    }

    if ((u8)globalCtrl != (s32)(lbl_803DC838 / 5)) {
        objectChannel = gSfxObjectChannels;
        lbl_803DC838 = (u8)(globalCtrl * 5);
        i = SFX_OBJECT_CHANNEL_COUNT - 1;
        do {
            if ((objectChannel->handle != (u32)-1) && (objectChannel->globalCtrlDisabled == 0)) {
                sndFXCtrl(objectChannel->handle, 0x5B, lbl_803DC838);
            }
            objectChannel++;
        } while (i-- != 0);
    }

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if ((objectChannel->handle != (u32)-1) && (objectChannel->hasPosition != 0)) {
            if (objectChannel->tracksObjectPosition != 0) {
                if ((*(u16*)(objectChannel->object + 0xB0) & SFX_LOOPED_OBJECT_STOP_FLAG) != 0) {
                    objectChannel->tracksObjectPosition = 0;
                } else {
                    objectChannel->x = *(f32*)(objectChannel->object + 0x18);
                    objectChannel->y = *(f32*)(objectChannel->object + 0x1C);
                    objectChannel->z = *(f32*)(objectChannel->object + 0x20);
                }
            }

            if ((objectChannel->tracksObjectPosition != 0) || (objectChannel->globalCtrlDisabled != 0)) {
                Sfx_UpdateObjectChannel3D(objectChannel);
            }
        }
        objectChannel++;
    } while (i-- != 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Sfx_InitObjectChannels(void)
{
    SfxObjectChannel* objectChannel;
    s32 i;

    i = SFX_OBJECT_CHANNEL_COUNT;
    objectChannel = &gSfxObjectChannels[SFX_OBJECT_CHANNEL_COUNT];
    goto checkNextChannel;
setChannelFree:
    objectChannel->handle = (u32)-1;
checkNextChannel:
    objectChannel--;
    if (i-- != 0) {
        goto setChannelFree;
    }

    gSfxObjectChannelAgeLo = 0;
    gSfxObjectChannelAgeHi = 0;
    objectChannel = gSfxObjectChannels;
    lbl_803DC838 = 0;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if ((objectChannel->handle != (u32)-1) && (objectChannel->globalCtrlDisabled == 0)) {
            sndFXCtrl(objectChannel->handle, 0x5B, lbl_803DC838);
        }
        objectChannel++;
    } while (i-- != 0);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
SfxObjectChannel* Sfx_FindObjectChannel(u32 obj, u32 channel, u32 sfxId, s32 mode)
{
    SfxObjectChannel* objectChannel = gSfxObjectChannels;
    SfxObjectChannel* bestChannel = NULL;
    u64 bestAge;
    u32 channelMask = (u8)channel;
    s32 i;

    if (mode == 2) {
        bestAge = 0;
    } else {
        bestAge = (u64)-1;
    }
    gSfxObjectChannelMatchCount = 0;

    for (i = SFX_OBJECT_CHANNEL_COUNT; i != 0; i--) {
        if ((objectChannel->handle != (u32)-1) &&
            ((obj == 0) || (objectChannel->object == obj)) &&
            ((channelMask == 0) || ((objectChannel->channelMask & channelMask) != 0)) &&
            (((u16)sfxId == 0) || (objectChannel->sfxId == (u16)sfxId))) {
            gSfxObjectChannelMatchCount++;

            switch (mode) {
            case 2:
                if (objectChannel->age > bestAge) {
                    bestChannel = objectChannel;
                    bestAge = objectChannel->age;
                }
                break;
            case 0:
                return objectChannel;
            case 1:
            case 3:
                if (objectChannel->age < bestAge) {
                    bestChannel = objectChannel;
                    bestAge = objectChannel->age;
                }
                break;
            }

            if ((mode != 3) && (gSfxObjectChannelMatchCount == 3)) {
                return bestChannel;
            }
        }
        objectChannel++;
    }

    return bestChannel;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int concatThreeStrings(char* dst, void* unused, const char* first, const char* second, const char* third)
{
    strcpy(dst, first);
    strcat(dst, second);
    strcat(dst, third);
    return 1;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80009008(void)
{
    lbl_803DC7BC = 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80008EDC(TextCallbackEntry* p)
{
    int i;
    TextCallbackEntry* e = lbl_80335940;
    for (i = 0; i < 16; i++) {
        if (p == e) {
            e->fn(e->a, e->b, e->c);
            return;
        }
        e++;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void audioSetVolumes(u8 volume, u16 time, int musicFlag, int fxFlag, int streamFlag)
{
    if (musicFlag != 0 || fxFlag != 0) {
        sndMasterVolume(volume, time, musicFlag, fxFlag);
    }
    if (streamFlag != 0) {
        AudioStream_SetVolume(volume);
        AudioStream_SetDefaultVolume(volume);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void MIDIWADLoadedCallback(int status, void* fileInfo)
{
    if (status == -1) {
        OSReport(sMidiWadLoadedCallbackLoadError);
        DVDClose(fileInfo);
        mm_free(fileInfo);
    } else {
        DVDClose(fileInfo);
        mm_free(fileInfo);
        gAudioPendingLoadFlags &= ~0x800;
        gAudioCompletedLoadFlags |= 0x800;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int musicInitMidiWad(void)
{
    MusicTrackSlot *table;
    MusicTrackSlot *found;
    MusicChannel *ch;
    int track, j;
    int size;
    int arenaOffset;
    int saved;
    int i;

    if (!gMidiWadLoadStarted) {
        gMidiWadLoadStarted = 1;
        ch = gMusicChannels;
        for (i = 0; i < 16; i++) {
            ch->field_0 = -1;
            ch->seqHandle = -1;
            ch->bankData = NULL;
            ch->voiceId = 0xff;
            ch->status = 0;
            ch->field_12 = 0;
            *(int *)&ch->pad14[4] = 0;
            ch++;
        }
        lbl_803DC814 = 1;
        lbl_803DC818 = 1;
        gAudioPendingLoadFlags |= 0x800;
        saved = testAndSet_onlyUseHeap3(0);
        gMidiWadFileData = loadFileByPathAsync(sMidiWadPath, &gMidiWadLoadedSize, 0,
                                               (void (*)(void *))MIDIWADLoadedCallback);
        testAndSet_onlyUseHeap3(saved);
    }
    if (gAudioCompletedLoadFlags & 0x800) {
        size = gMidiWadLoadedSize;
        if (size & 0x1f) {
            size = (size | 0x1f) + 1;
        }
        gMidiWadPayloadStart = (u8 *)gMidiWadFileData + 0x1a0;
        gMidiWadPayloadSize = size - 0x1a0;
        gMidiWadArenaSize = 0x1000000 - gMidiWadPayloadSize;
        arenaOffset = gMidiWadArenaSize;
        table = (MusicTrackSlot *)sMusicTrackTable;
        for (track = 0; track <= 0x63; track++) {
            found = NULL;
            for (j = 0; j < 0x64; j++) {
                if (track == table[j].id) {
                    found = &table[j];
                    break;
                }
            }
            if (found != NULL) {
                found->offset = arenaOffset;
                found->size = ((int *)gMidiWadFileData)[track];
            }
            size = found->size;
            if (size & 0x1f) {
                size = (size | 0x1f) + 1;
            }
            arenaOffset += size;
        }
        fn_80008F38(gMidiWadPayloadStart, gMidiWadArenaSize, gMidiWadPayloadSize);
        saved = mmSetFreeDelay(0);
        mm_free(gMidiWadFileData);
        mmSetFreeDelay(saved);
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void poolDataMLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sPoolDataMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x8;
        gAudioCompletedLoadFlags |= 0x8;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void poolDataSLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sPoolDataSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x80;
        gAudioCompletedLoadFlags |= 0x80;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void projectDataMLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sProjectDataMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x10;
        gAudioCompletedLoadFlags |= 0x10;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void projectDataSLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sProjectDataSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x100;
        gAudioCompletedLoadFlags |= 0x100;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void sampleBufferMLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSampleBufferMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x40;
        gAudioCompletedLoadFlags |= 0x40;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void sampleBufferSLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSampleBufferSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x400;
        gAudioCompletedLoadFlags |= 0x400;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void sampleDirectoryMLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSampleDirectoryMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x20;
        gAudioCompletedLoadFlags |= 0x20;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void sampleDirectorySLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSampleDirectorySLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x200;
        gAudioCompletedLoadFlags |= 0x200;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void sfxTriggersLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSfxTriggersLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x2;
        gAudioCompletedLoadFlags |= 0x2;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void musicTriggersLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sMusicTriggersLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x1;
        gAudioCompletedLoadFlags |= 0x1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void streamsLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sStreamsLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        StreamEntry* s;
        int count;
        int i;
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x4;
        gAudioCompletedLoadFlags |= 0x4;
        s = gStreamsData;
        count = gStreamsCount;
        for (i = 0; i < count; i++) {
            s->flag = 0;
            s++;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80008F38(void* addr, u32 dest, u32 size)
{
    int idx;
    TextCallbackEntry* entry;
    idx = lbl_803DC7B8;
    lbl_803DC7B8 = idx + 1;
    entry = &lbl_80335940[idx];
    if (idx + 1 >= 0x10) {
        lbl_803DC7B8 = 0;
    }
    if ((size & 0x1f) != 0) {
        size = (size | 0x1f) + 1;
    }
    DCFlushRange(addr, size);
    lbl_803DC7BC = 0;
    ARQPostRequest(entry, 0x64, 0, 1, (u32)addr, dest, size, (void (*)(void*))fn_80009008);
    while (lbl_803DC7BC == 0) {
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void audioAllocFn_80008df4(void* source, u32 size, void** outBuf, u32 cb, u32 p5, u32 p6, u32 p7)
{
    int idx;
    TextCallbackEntry* entry;
    void* buf;
    idx = lbl_803DC7B8;
    lbl_803DC7B8 = idx + 1;
    entry = &lbl_80335940[idx];
    if (idx + 1 >= 0x10) {
        lbl_803DC7B8 = 0;
    }
    if ((size & 0x1f) != 0) {
        size = (size | 0x1f) + 1;
    }
    buf = mmAlloc(size, 0, NULL);
    *outBuf = buf;
    entry->fn = (void (*)(int, int, int))cb;
    entry->a = p5;
    entry->b = p6;
    entry->c = p7;
    DCFlushRange(buf, size);
    lbl_803DC7BC = 0;
    ARQPostRequest(entry, 0x64, 1, 1, (u32)source, (u32)buf, size, (void (*)(void*))fn_80008EDC);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Sfx_ResolveObjectSfxId(int* outChannel, u16* sfxId)
{
    switch (*sfxId) {
    case 0x170:
    case 0xca:
    case 0x109:
        *sfxId = 0x409;
    case 0x409:
        *outChannel = 0;
        return 1;
    case 0x7e:
    case 0x487:
        *outChannel = 0;
        return 1;
    case 0x420:
        Music_Trigger(0xe7, 0);
        Music_Trigger(0xe7, 1);
        return 0;
    case 0x38c:
        return !(gAudioActiveChannelMask & 4);
    case 0x0:
        return 0;
    default:
        return 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u32 Sfx_PlayFromObjectLimited(u32 obj, u32 sfxId, int limit)
{
    SfxObjectChannel* ch = Sfx_FindObjectChannel(0, 0, sfxId, 3);
    if (ch != NULL && (int)gSfxObjectChannelMatchCount > limit) {
        sndFXKeyOff(*(s32*)ch);
        *(s32*)ch = -1;
    }
    if ((int)gSfxObjectChannelMatchCount < limit) {
        Sfx_PlayFromObjectEx(obj, NULL, 0, sfxId);
    }
    return gSfxObjectChannelMatchCount;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int AudioStream_Play(int id, void (*preparedCallback)(void))
{
    char path[64];
    u8* dvd = lbl_80336C40;
    int* fadeTbl = lbl_802C5DB8;
    StreamEntry* s = gStreamsData;
    int count = gStreamsCount;
    int slot = -1;
    int i;
    u8 vol;
    u8 stopped;

    if (id == 1228) {
        return 0;
    }
    if (id == 1318) {
        Music_Trigger(0xA8, 0);
        Music_Trigger(0xF4, 1);
    }
    if ((int)audioFlagFn_8000a188(8)) {
        return 0;
    }

    for (i = count; i != 0; i--) {
        if (s->id == id) {
            slot = (s - gStreamsData) + 1;
            break;
        }
        s++;
    }

    if (slot == -1) {
        return 0;
    }
    if (gAudioStreamDvdState != 0) {
        return 0;
    }
    gAudioStreamDvdState = 0;

    if (concatThreeStrings(path, (void*)0x40, (char*)fadeTbl + 0x3C, s->name,
                           sAdpExtension) == 0) {
        return 0;
    }
    if (DVDOpen(path, dvd + 0x90) == 0) {
        return 0;
    }

    if (gAudioStreamCurrentId != 0) {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(dvd, AudioStream_CancelCallback) == 0) {
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
    } else {
        gAudioStreamPlaying = 0;
    }

    gAudioStreamEndPos = (f32)(u32)s->lengthRaw / lbl_803DE5D4;
    if (gAudioStreamEndPos == lbl_803DE5D0) {
        gAudioStreamEndPos = lbl_803DE5D8;
    }

    gAudioStreamMusicFadeFlagA = fadeTbl[(s->fadeBits >> 6) & 3] != 0 ? 1 : 0;
    gAudioStreamMusicFadeFlagB = fadeTbl[(s->fadeBits >> 4) & 3] != 0 ? 1 : 0;
    if ((s->fadeBits >> 2) & 3) {
        Sfx_StopAllObjectSounds();
    }
    gAudioActiveChannelMask = ((s->volBits >> 7) & 1) ? 4 : 0;

    stopped = 0;
    while (gAudioStreamPlaying != 0) {
        padUpdate();
        checkReset();
        if (stopped) {
            mmFreeTick(0);
            waitNextFrame();
        }
        dvdCheckError();
        if (stopped) {
            gameTextRun();
            GXFlush_(1, 0);
        }
        if (lbl_803DC950 != 0) {
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
    DVDPrepareStreamAsync(lbl_80336C40 + 0x90, 0, 0, AudioStream_PrepareCallback);
    DVDStopStreamAtEndAsync(lbl_80336C40 + 0x60, 0);
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Music_Trigger(int id, int arg)
{
    MusicTrigger *trigger;
    MusicChannel *channel;
    int i;
    int found;

    if (arg != 1 && arg != 0) {
        return;
    }
    trigger = gMusicTriggersData;
    i = gMusicTriggersCount;
    while (i != 0) {
        if ((int)trigger->id == id) {
            goto foundTrigger;
        }
        trigger++;
        i--;
    }
    trigger = NULL;
foundTrigger:
    if (trigger == NULL) {
        return;
    }
    if (id == 0xeb && arg == 1) {
        channel = gMusicChannels;
        found = 0;
        for (i = 0; i < 16; i++) {
            if (channel->field_0 == 0x5e && channel->status != 0 && channel->status != 2 &&
                channel->status != 5) {
                found = 1;
                break;
            }
            channel++;
        }
        if (found) {
            return;
        }
        if (GameBit_Get(0xa7f)) {
            return;
        }
    }
    channel = gMusicChannels;
    found = 0;
    for (i = 0; i < 16; i++) {
        if (channel->field_0 == (int)trigger->track && channel->status != 0 &&
            channel->status != 2 && channel->status != 5) {
            found = 1;
            break;
        }
        channel++;
    }
    if (!found) {
        channel = NULL;
    }
    if (arg == 1) {
        if (channel == NULL) {
            Music_LoadChannelForTrigger(trigger);
            return;
        }
        if (channel->status != 1) {
            return;
        }
        sndSeqVolume(channel->pad14[0], *(u16 *)trigger->pad, channel->seqHandle, 0);
    } else if (channel != NULL) {
        if (channel->status == 2) {
            return;
        }
        if (channel->status == 4 || channel->status == 5) {
            channel->status = 5;
            return;
        }
        i = *(u16 *)trigger->pad;
        sndSeqVolume(0, i < 0x1f4 ? 0x1f4 : i, channel->seqHandle, 1);
        channel->status = 2;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
static void Music_FreeChannel(MusicChannel *ch)
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void streamFn_8000a380(int mask, int mode, int time)
{
    MusicChannel *ch = gMusicChannels;
    int i = 15;
    do {
        if (ch->status != 0 && ((ch->pad11 + 1) & mask) != 0) {
            switch (mode) {
            case 1:
                if (audioIsResetting() == 0) {
                    if (ch->status != 2) {
                        if (ch->status == 4 || ch->status == 5) {
                            ch->status = 5;
                        } else {
                            sndSeqVolume(0, 250, ch->seqHandle, 1);
                            ch->status = 2;
                        }
                    }
                } else if (ch->status == 4 || ch->status == 5) {
                    ch->status = 5;
                } else {
                    Music_FreeChannel(ch);
                }
                break;
            case 2:
                if (ch->status != 2) {
                    if (ch->status == 4 || ch->status == 5) {
                        ch->status = 5;
                    } else {
                        sndSeqVolume(0, (u16)(time < 500 ? 500 : time), ch->seqHandle, 1);
                        ch->status = 2;
                    }
                }
                break;
            }
        }
        ch++;
    } while (i-- != 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
static int Music_IsTriggerExcluded(int id)
{
    switch (id) {
    case 0x2b:
    case 0xbd:
    case 0xeb:
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Music_Update(void)
{
    MusicChannel *ch;
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
    do {
        int status = ch->status;
        if (status != 0 && status != 4) {
            if (gSynthVoices[ch->voiceId].field_8 == 0) {
                if (status == 4 || status == 5) {
                    ch->status = 5;
                } else {
                    Music_FreeChannel(ch);
                }
            }
        }
        switch (ch->status) {
        case 1:
        case 3:
        case 4:
            if (!Music_IsTriggerExcluded((*(MusicTrigger **)&ch->pad14[8])->id)) {
                if (ch->pad11 != 0) {
                    gMusicActivePriority = ch->field_12 < gMusicActivePriority
                                               ? ch->field_12
                                               : gMusicActivePriority;
                } else {
                    lowPriority =
                        ch->field_12 < lowPriority ? ch->field_12 : lowPriority;
                }
            }
            break;
        case 2:
            ch->field_20 += timeDelta / lbl_803DE564;
            if (ch->field_20 > lbl_803DE568) {
                if (ch->status == 4 || ch->status == 5) {
                    ch->status = 5;
                } else {
                    Music_FreeChannel(ch);
                }
            }
            break;
        }
        ch++;
    } while (i-- != 0);

    ch = gMusicChannels;
    for (i = 0; i < 16; i++) {
        switch (ch->status) {
        case 1:
        case 3:
        case 4:
            if (!Music_IsTriggerExcluded((*(MusicTrigger **)&ch->pad14[8])->id)) {
                if (ch->pad11 != 0) {
                    if (ch->field_12 == gMusicActivePriority &&
                        *(u32 *)&ch->pad14[4] > bestActive18) {
                        bestActive18 = *(u32 *)&ch->pad14[4];
                        activeVol = *(u16 *)(*(MusicTrigger **)&ch->pad14[8])->pad;
                    }
                } else {
                    if (ch->field_12 == lowPriority &&
                        *(u32 *)&ch->pad14[4] > bestLow18) {
                        bestLow18 = *(u32 *)&ch->pad14[4];
                        lowVol = *(u16 *)(*(MusicTrigger **)&ch->pad14[8])->pad;
                        if (ch->status != 3) {
                            found20 = 1;
                        }
                    }
                }
            }
            break;
        case 2:
            if (ch->pad11 != 0) {
                s2VolA = s2VolA > *(u16 *)(*(MusicTrigger **)&ch->pad14[8])->pad
                             ? s2VolA
                             : *(u16 *)(*(MusicTrigger **)&ch->pad14[8])->pad;
            } else {
                s2VolB = s2VolB > *(u16 *)(*(MusicTrigger **)&ch->pad14[8])->pad
                             ? s2VolB
                             : *(u16 *)(*(MusicTrigger **)&ch->pad14[8])->pad;
                found19 = 1;
            }
            break;
        }
        ch++;
    }

    if (found20) {
        activeVol = lowVol;
    }
    if (found19) {
        s2VolA = s2VolB;
    }
    if ((int)fadeB != 0) {
        if (activeVol >= 0x1f4) {
            activeVol = 0x1f4;
        }
    }
    if ((int)fadeA != 0) {
        if (lowVol >= 0x1f4) {
            lowVol = 0x1f4;
        }
    }

    ch = gMusicChannels;
    i = 0xf;
    do {
        int st = ch->status;
        switch (st) {
        case 1:
        case 3:
            if (ch->pad11 != 0) {
                if (ch->field_12 == gMusicActivePriority &&
                    *(u32 *)&ch->pad14[4] < bestActive18) {
                    if (st != 2) {
                        if (st == 4 || st == 5) {
                            ch->status = 5;
                        } else {
                            sndSeqVolume(0, (u16)(activeVol < 0x1f4 ? 0x1f4 : activeVol),
                                         ch->seqHandle, 1);
                            ch->status = 2;
                        }
                    }
                } else if (ch->field_12 > gMusicActivePriority ||
                           ch->field_12 > lowPriority || (int)fadeB != 0) {
                    if (st != 3) {
                        sndSeqVolume(0, (u16)(activeVol < 0x1f4 ? 0x1f4 : activeVol),
                                     ch->seqHandle, (u8)(ch->pad11 != 0 ? 0 : 2));
                        ch->status = 3;
                    }
                } else {
                    if (st != 1) {
                        sndSeqMute(ch->seqHandle, -1, -1);
                        sndSeqContinue(ch->seqHandle);
                        sndSeqVolume((u8)*(u16 *)&ch->pad14[0],
                                     (u16)(s2VolA < 0x1f4 ? 0x1f4 : s2VolA),
                                     ch->seqHandle, 0);
                        ch->status = 1;
                    }
                }
            } else {
                if (ch->field_12 == lowPriority &&
                    *(u32 *)&ch->pad14[4] < bestLow18) {
                    if (st != 2) {
                        if (st == 4 || st == 5) {
                            ch->status = 5;
                        } else {
                            sndSeqVolume(0, (u16)(lowVol < 0x1f4 ? 0x1f4 : lowVol),
                                         ch->seqHandle, 1);
                            ch->status = 2;
                        }
                    }
                } else if (ch->field_12 > lowPriority ||
                           ch->field_12 > gMusicActivePriority || (int)fadeA != 0) {
                    if (st != 3) {
                        sndSeqVolume(0, (u16)(lowVol < 0x1f4 ? 0x1f4 : lowVol),
                                     ch->seqHandle, (u8)(ch->pad11 != 0 ? 0 : 2));
                        ch->status = 3;
                    }
                } else {
                    if (st != 1) {
                        sndSeqMute(ch->seqHandle, -1, -1);
                        sndSeqContinue(ch->seqHandle);
                        sndSeqVolume((u8)*(u16 *)&ch->pad14[0],
                                     (u16)(s2VolB < 0x1f4 ? 0x1f4 : s2VolB),
                                     ch->seqHandle, 0);
                        ch->status = 1;
                    }
                }
            }
            break;
        }
        ch++;
    } while (i-- != 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Music_LoadChannelForTrigger(MusicTrigger *trigger)
{
    MusicTrackSlot *slot;
    MusicChannel *channel;
    int counter;
    int i;

    if ((trigger->pad[0xb] >> 5) & 1) {
        if (audioFlagFn_8000a188(2)) {
            return;
        }
    }
    if (!((trigger->pad[0xb] >> 5) & 1)) {
        if (audioFlagFn_8000a188(1)) {
            return;
        }
    }
    slot = (MusicTrackSlot *)sMusicTrackTable;
    for (i = 0; i < 100; i++) {
        if (slot->id == (int)trigger->track) {
            goto foundSlot;
        }
        slot++;
    }
    slot = NULL;
foundSlot:
    if (slot == NULL) {
        return;
    }
    channel = gMusicChannels;
    for (i = 0; i < 16; i++) {
        if (channel->status == 0) {
            goto foundChannel;
        }
        channel++;
    }
    channel = NULL;
foundChannel:
    if (channel == NULL) {
        return;
    }
    channel->field_0 = trigger->track;
    *(u16 *)&channel->pad14[0] = trigger->pad[8];
    channel->pad11 = (trigger->pad[0xb] >> 5) & 1;
    channel->status = 4;
    channel->field_12 = trigger->pad[9];
    if (channel->pad11) {
        counter = lbl_803DC814++;
    } else {
        counter = lbl_803DC818++;
    }
    *(int *)&channel->pad14[4] = counter;
    *(MusicTrigger **)&channel->pad14[8] = trigger;
    channel->field_20 = lbl_803DE560;
    audioAllocFn_80008df4((void *)slot->offset, slot->size, &channel->bankData,
                          (u32)Music_ChannelLoadedCallback, (u32)slot, (u32)channel, (u32)trigger);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Music_PlayTrackByIndex(int index)
{
    MusicTrigger* trigger = gMusicTriggersData;
    int count = gMusicTriggersCount;
    while (count != 0) {
        if ((int)trigger->id == 0xec) {
            goto found;
        }
        trigger++;
        count--;
    }
    trigger = NULL;
found:
    streamFn_8000a380(3, 1, 0);
    trigger->track = *(s16*)((u8*)sMusicTrackTable + (index << 4));
    Music_Trigger(0xec, 1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void audioSetSoundMode(int mode, u8 forceFlag)
{
    if (forceFlag == 0) {
        if (OSGetSoundMode() != 1) {
            return;
        }
    }
    if ((u8)mode != gAudioSoundMode) {
        switch ((u8)mode) {
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
    if ((u8)mode == 2) {
        if (gAudioSoundMode != 2) {
            OSSetSoundMode(0);
        }
    } else {
        if (gAudioSoundMode == 2) {
            OSSetSoundMode(1);
        }
    }
    gAudioSoundMode = (s8)mode;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void audioLoadTriggerData(void)
{
    char* base = sSampleBufferSLoadedCallbackLoadError;
    int info;
    int delay;
    if (gMusicTriggersData != NULL) {
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
    gStreamsCount = (u32)info / 0xb0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int audioInit(void)
{
    char *base = sSampleBufferSLoadedCallbackLoadError;
    int hooks[2];
    int reverbWork;
    int delay;
    int v;

    hooks[0] = lbl_803DE548;
    hooks[1] = lbl_803DE54C;
    if (!gAudioInitStarted) {
        gAudioInitStarted = 1;
        gAudioPendingLoadFlags = 0;
        gAudioCompletedLoadFlags = 0;
        testAndSet_onlyUseHeap3(1);
        if (gAudioHardwareInitialized) {
            return 1;
        }
        gAudioHardwareInitialized = 1;
        ARInit(lbl_80335D94, 0xa);
        ARQInit();
        AIInit(0);
        AISetDSPSampleRate(0);
        sndSetHooks(hooks);
        sndInit(0x30, 0x30, 0x18, 1, 1, 0x1000000);
        sndSetMaxVoices(0x30, 0x18);
        if (OSGetSoundMode() == 0) {
            gAudioSoundMode = 2;
            sndOutputMode(0);
        } else {
            gAudioSoundMode = 0;
            sndOutputMode(1);
        }
        lbl_80335C40[0x13c] = 0;
        *(f32 *)&lbl_80335C40[0x148] = lbl_803DE550;
        *(f32 *)&lbl_80335C40[0x150] = lbl_803DE554;
        *(f32 *)&lbl_80335C40[0x14c] = lbl_803DE558;
        *(f32 *)&lbl_80335C40[0x140] = lbl_803DE558;
        *(f32 *)&lbl_80335C40[0x144] = lbl_803DE55C;
        sndAuxCallbackUpdateSettingsReverbSTD(lbl_80335C40);
        reverbWork = 0;
        sndSetAuxProcessingCallbacks(0, (void *)sndAuxCallbackReverbSTD, lbl_80335C40, 0xff, 0, 0, 0,
                                     0xff, reverbWork);
        if (!sndIsInstalled()) {
            OSReport(base + 0x1f8);
            return 0xff;
        }
        sndVolume(0x7f, 0, 0xff);
        sndMasterVolume(0x7f, 0x64, 1, 1);
        Sfx_InitObjectChannels();
        AudioStream_Init();
        audioLoadTriggerData();
        testAndSet_onlyUseHeap3(1);
        gAudioPendingLoadFlags |= 0x8;
        gAudioStarfoxMPoolDataHandle = loadFileByPathAsync(base + 0x228, NULL, 0,
                                                           (void (*)(void *))poolDataMLoadedCallback);
        gAudioPendingLoadFlags |= 0x10;
        gAudioStarfoxMProjectDataHandle = loadFileByPathAsync(base + 0x23c, NULL, 0,
                                                             (void (*)(void *))projectDataMLoadedCallback);
        gAudioPendingLoadFlags |= 0x20;
        gAudioStarfoxMSampleDirectoryHandle = loadFileByPathAsync(base + 0x250, NULL, 0,
                                                                 (void (*)(void *))sampleDirectoryMLoadedCallback);
        testAndSet_onlyUseHeap3(0);
        gAudioPendingLoadFlags |= 0x40;
        gAudioStarfoxMSampleBufferHandle = loadFileByPathAsync(base + 0x264, NULL, 0,
                                                              (void (*)(void *))sampleBufferMLoadedCallback);
        if (gAudioStarfoxMPoolDataHandle == NULL || gAudioStarfoxMProjectDataHandle == NULL ||
            gAudioStarfoxMSampleDirectoryHandle == NULL || gAudioStarfoxMSampleBufferHandle == NULL) {
            return 0xff;
        }
        testAndSet_onlyUseHeap3(0);
    }
    if (!gAudioMusicGroupReady && (gAudioCompletedLoadFlags & 0x8) && (gAudioCompletedLoadFlags & 0x10) &&
        (gAudioCompletedLoadFlags & 0x8) && (gAudioCompletedLoadFlags & 0x20) &&
        (gAudioCompletedLoadFlags & 0x40)) {
        sndPushGroup(gAudioStarfoxMProjectDataHandle, 0, gAudioStarfoxMSampleBufferHandle,
                     gAudioStarfoxMSampleDirectoryHandle, gAudioStarfoxMPoolDataHandle);
        delay = mmSetFreeDelay(0);
        mm_free(gAudioStarfoxMSampleBufferHandle);
        mmSetFreeDelay(delay);
        gAudioMusicGroupReady = 1;
        testAndSet_onlyUseHeap3(1);
        gAudioPendingLoadFlags |= 0x80;
        gAudioStarfoxSPoolDataHandle = loadFileByPathAsync(base + 0x278, NULL, 0,
                                                          (void (*)(void *))poolDataSLoadedCallback);
        gAudioPendingLoadFlags |= 0x100;
        gAudioStarfoxSProjectDataHandle = loadFileByPathAsync(base + 0x28c, NULL, 0,
                                                             (void (*)(void *))projectDataSLoadedCallback);
        gAudioPendingLoadFlags |= 0x200;
        gAudioStarfoxSSampleDirectoryHandle = loadFileByPathAsync(base + 0x2a0, NULL, 0,
                                                                 (void (*)(void *))sampleDirectorySLoadedCallback);
        testAndSet_onlyUseHeap3(0);
        gAudioPendingLoadFlags |= 0x400;
        gAudioStarfoxSSampleBufferHandle = loadFileByPathAsync(base + 0x2b4, NULL, 0,
                                                              (void (*)(void *))sampleBufferSLoadedCallback);
        if (gAudioStarfoxSPoolDataHandle == NULL || gAudioStarfoxSProjectDataHandle == NULL ||
            gAudioStarfoxSSampleDirectoryHandle == NULL || gAudioStarfoxSSampleBufferHandle == NULL) {
            return 0xff;
        }
    }
    if (!gAudioSfxGroupsReady && (gAudioCompletedLoadFlags & 0x80) && (gAudioCompletedLoadFlags & 0x100) &&
        (gAudioCompletedLoadFlags & 0x80) && (gAudioCompletedLoadFlags & 0x200) &&
        (gAudioCompletedLoadFlags & 0x400)) {
        for (v = 1; v <= 0x37; v++) {
            if (sndPushGroup(gAudioStarfoxSProjectDataHandle, (u16)v, gAudioStarfoxSSampleBufferHandle,
                             gAudioStarfoxSSampleDirectoryHandle, gAudioStarfoxSPoolDataHandle) == 0) {
                OSReport(base + 0x2c8, v);
            }
        }
        delay = mmSetFreeDelay(0);
        mm_free(gAudioStarfoxSSampleBufferHandle);
        mmSetFreeDelay(delay);
        gAudioSfxGroupsReady = 1;
    }
    if (!gAudioReady && gAudioMusicGroupReady && gAudioSfxGroupsReady) {
        gAudioReady = musicInitMidiWad();
    }
    if (gAudioReady && gAudioMusicGroupReady && gAudioSfxGroupsReady &&
        (gAudioCompletedLoadFlags & 0x1) && (gAudioCompletedLoadFlags & 0x2) &&
        (gAudioCompletedLoadFlags & 0x4)) {
        gAudioResetting = 0;
        gAudioManagedChannelMask = 0x1f;
        gAudioActiveChannelMask = 0;
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
