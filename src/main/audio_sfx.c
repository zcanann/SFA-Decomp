#include "main/audio/sfx.h"
#include "musyx/mcmd.h"
#include "musyx/snd_synth_api.h"
#include "main/audio_internal.h"
#include "main/camera.h"
#include "main/gamebits.h"
#include "main/gameloop_api.h"
#include "sys/objects.h"
#include "main/objseq_api.h"
#include "main/vecmath.h"
#define SYNTH_INTERNAL_USE_PROJECT_TYPES
#include "src/musyx/runtime/synth_internal.h"
#include "game/objects/object.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/mtx/vec.h"
#include "main/audio/music_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_stop_object_api.h"

u8 gSfxTriggerExtraTable[8] = {1, 2, 4, 8, 0x10, 0x20, 0x40, 0};

u64 gSfxObjectChannelAge;
u32 gSfxObjectChannelMatchCount;
u8 gSfxGlobalReverbLevel;
int gSfxTriggersCount;
void* gSfxTriggersData;

SfxObjectChannel gSfxObjectChannels[SFX_OBJECT_CHANNEL_COUNT];

static void Sfx_RotateVectorByAngles(s16 angX, s16 angY, s16 angZ, Vec* vector);
static f32 Sfx_GetListenerRelativeDistance(Vec* soundPos, Vec* outDelta);

static inline SfxObjectChannel* Sfx_FindFreeObjectChannel(void)
{
    SfxObjectChannel* ch = gSfxObjectChannels;
    s32 i;
    for (i = SFX_OBJECT_CHANNEL_COUNT - 1; i >= 0; i--)
    {
        if (ch->handle == (u32)-1)
        {
            return ch;
        }
        ch++;
    }
    return NULL;
}


u32 Sfx_PlayFromObjectLimited(GameObject* obj, u16 sfxId, int limit)
{
    SfxObjectChannel* ch = Sfx_FindObjectChannel(0, 0, sfxId, 3);
    if (ch != NULL && (int)gSfxObjectChannelMatchCount > limit)
    {
        sndFXKeyOff(*(s32*)ch);
        *(s32*)ch = -1;
    }
    if ((int)gSfxObjectChannelMatchCount < limit)
    {
        Sfx_PlayFromObjectEx(obj, NULL, 0, sfxId);
    }
    return gSfxObjectChannelMatchCount;
}

int Sfx_IsPlayingFromObjectChannel(GameObject* obj, int channel)
{
    SfxObjectChannel* objectChannel;

    if (((u8)channel == 0) || (obj == NULL))
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

s32 Sfx_IsPlayingFromObject(GameObject* obj, u16 sfxId)
{
    SfxObjectChannel* objectChannel;

    if (sfxId != 0)
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

void Sfx_StopAllObjectSounds(void)
{
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT;
    while (i-- != 0)
    {
        if (objectChannel->handle != (u32)-1)
        {
            sndFXKeyOff(objectChannel->handle);
            objectChannel->handle = (u32)-1;
        }
        objectChannel++;
    }
}

void Sfx_SetObjectReverbPreset(u32 preset)
{
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    gSfxGlobalReverbLevel = (u8)(preset * 5);
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do
    {
        if ((objectChannel->handle != (u32)-1) && (objectChannel->globalCtrlDisabled == 0))
        {
            sndFXCtrl(objectChannel->handle, MCMD_CTRL_REVERB, gSfxGlobalReverbLevel);
        }
        objectChannel++;
    } while (i-- != 0);
}

void Sfx_SetObjectSoundsPaused(s32 paused)
{
    u8 pausedByte;
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    pausedByte = paused;

    do {
        if (objectChannel->handle != (u32)-1)
        {
            if (paused != 0)
            {
                sndFXCtrl(objectChannel->handle, MCMD_CTRL_VOLUME, 0);
            }
            else if (objectChannel->paused != 0)
            {
                sndFXCtrl(objectChannel->handle, MCMD_CTRL_VOLUME, objectChannel->volume);
            }
            objectChannel->paused = pausedByte;
        }
        objectChannel++;
    } while (i-- != 0);
}

void Sfx_StopObjectChannel(GameObject* obj, int channel)
{
    SfxObjectChannel* objectChannel;

    if ((u8)channel == 0 || obj == 0)
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
        objectChannel->handle = (u32)-1;
    }
}

void Sfx_StopFromObject(GameObject* obj, u16 sfxId)
{
    SfxObjectChannel* objectChannel;

    if (sfxId != 0)
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
        objectChannel->handle = (u32)-1;
    }
}


void Sfx_SetObjectChannelVolume(GameObject* obj, u32 channel, u8 volume, f32 volumeScale)
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
                sndFXCtrl(objectChannel->handle, MCMD_CTRL_VOLUME, (u8)ctrlVolume);
            }
        }

        if (volumeScale < 0.0f)
        {
            volumeScale = 0.0f;
        }
        if (volumeScale > 1.0f)
        {
            volumeScale = 1.0f;
        }
        sndFXCtrl14(objectChannel->handle, 0x80, 16383.0f * volumeScale);
    }
}

void Sfx_SetObjectSfxVolume(GameObject* obj, u16 sfxId, u8 volume, f32 volumeScale)
{
    u8 volumeByte;
    SfxObjectChannel* objectChannel;

    volumeByte = volume;
    if (sfxId != 0) {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 2);
    } else {
        objectChannel = NULL;
    }

    if (objectChannel != NULL) {
        if (volumeByte != 0xFE) {
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
                sndFXCtrl(objectChannel->handle, MCMD_CTRL_VOLUME, (u8)ctrlVolume);
            }
        }

        if (volumeScale < 0.0f)
        {
            volumeScale = 0.0f;
        }
        if (volumeScale > 1.0f)
        {
            volumeScale = 1.0f;
        }
        sndFXCtrl14(objectChannel->handle, 0x80, 16383.0f * volumeScale);
    }
}

void Sfx_PlayFromObjectChannel(GameObject* obj, u32 channel, u16 sfxId)
{
    Sfx_PlayFromObjectEx(obj, NULL, channel, sfxId);
}

void Sfx_PlayAtPositionFromObject(GameObject* obj, f32 x, f32 y, f32 z, u16 sfxId)
{
    Vec pos;
    pos.x = x;
    pos.y = y;
    pos.z = z;

    Sfx_PlayFromObjectEx(obj, &pos, 0, sfxId);
}

void Sfx_PlayFromObject(GameObject* obj, u16 sfxId)
{
    Sfx_PlayFromObjectEx(obj, NULL, 0, sfxId);
}


void Sfx_UpdateObjectSounds(void)
{
    SfxObjectChannel* objectChannel;
    SfxObjectChannel* ch;
    s32 i;
    u32 globalCtrl;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT;
    while (i-- != 0)
    {
        if (objectChannel->handle != (u32)-1)
        {
            ch = (SfxObjectChannel*)sndFXCheck(objectChannel->handle);
            if ((u32)ch == (u32)-1)
            {
                objectChannel->handle = (u32)-1;
            }
        }
        objectChannel++;
    }

    if (mainGetBit(GAMEBIT_SHRINE_MUSIC_LOCK) != 0)
    {
        globalCtrl = 0xE;
    }
    else if (mainGetBit(GAMEBIT_IN_KRAZOA_SHRINE) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (mainGetBit(GAMEBIT_MC_IsActive) != 0)
    {
        globalCtrl = 0xD;
    }
    else if (mainGetBit(GAMEBIT_SETPIECE_ACTIVE) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (mainGetBit(GAMEBIT_WMRelated0A7F) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (mainGetBit(GAMEBIT_MAZEWELL_ACTIVE) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (mainGetBit(GAMEBIT_PlayerInShop) != 0)
    {
        globalCtrl = 0xC;
    }
    else if (mainGetBit(0xDCF) != 0)
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

    if ((u8)globalCtrl != (s32)(gSfxGlobalReverbLevel / 5))
    {
        objectChannel = gSfxObjectChannels;
        gSfxGlobalReverbLevel = (u8)((u8)globalCtrl * 5);
        i = SFX_OBJECT_CHANNEL_COUNT;
        while (i-- != 0)
        {
            if ((objectChannel->handle != (u32)-1) && (objectChannel->globalCtrlDisabled == 0))
            {
                sndFXCtrl(objectChannel->handle, MCMD_CTRL_REVERB, gSfxGlobalReverbLevel);
            }
            objectChannel++;
        }
    }

    ch = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT;
    while (i-- != 0)
    {
        if (ch->handle != (u32)-1 && ch->hasPosition != 0)
        {
            if (ch->tracksObjectPosition != 0)
            {
                if ((ch->object->objectFlags & SFX_LOOPED_OBJECT_STOP_FLAG) != 0)
                {
                    ch->tracksObjectPosition = 0;
                }
                else
                {
                    ch->pos.x = ch->object->anim.worldPosX;
                    ch->pos.y = ch->object->anim.worldPosY;
                    ch->pos.z = ch->object->anim.worldPosZ;
                }
            }

            if ((ch->tracksObjectPosition != 0) || (ch->globalCtrlDisabled != 0))
            {
                Sfx_UpdateObjectChannel3D(ch);
            }
        }
        ch++;
    }
}

static inline void Sfx_SetGlobalReverbLevel(u8 level)
{
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    gSfxGlobalReverbLevel = level;
    i = SFX_OBJECT_CHANNEL_COUNT;
    while (i-- != 0)
    {
        if ((objectChannel->handle != (u32)-1) && (objectChannel->globalCtrlDisabled == 0))
        {
            sndFXCtrl(objectChannel->handle, MCMD_CTRL_REVERB, gSfxGlobalReverbLevel);
        }
        objectChannel++;
    }
}

void Sfx_InitObjectChannels(void)
{
    s32 n;

    n = SFX_OBJECT_CHANNEL_COUNT;
    while (n-- != 0)
    {
        gSfxObjectChannels[n].handle = (u32)-1;
    }

    gSfxObjectChannelAge = 0;
    Sfx_SetGlobalReverbLevel(0);
}

void Sfx_PlayFromObjectEx(GameObject* obj, Vec* pos, u32 channel, u16 sfxId)
{
    u16 outSfxId;
    u8 vol;
    f32 pitch;
    f32 nearDist;
    f32 farDist;
    int channelMask;
    int stealExisting;
    int globalCtrlDisabled;
    SfxObjectChannel* found;
    SfxObjectChannel* ch;
    int tracksObj;

    tracksObj = 0;
    if (!Sfx_ResolveObjectSfxId(&obj, &sfxId)) {
        return;
    }
    if (!Sfx_ReadTriggerParams((SfxTriggerFull*)Sfx_FindTrigger(sfxId), &outSfxId, &vol, &pitch, &nearDist, &farDist,
                               &channelMask, &stealExisting, &globalCtrlDisabled)) {
        return;
    }
    if (obj != 0 && pos == NULL) {
        pos = &obj->anim.worldPos;
        tracksObj = 1;
    }
    if (pos != NULL) {
        Vec delta;
        f32 maxDist = farDist;
        if (!(Sfx_GetListenerRelativeDistance(pos, &delta) <= maxDist)) {
            return;
        }
    }
    if ((u8)channel != 0)
    {
        channelMask = (u8)channel;
    }
    if (obj != 0 && channelMask != 0)
    {
        if ((u8)channelMask == 0 || obj == 0)
        {
            found = NULL;
        }
        else
        {
            found = Sfx_FindObjectChannel(obj, (u8)channelMask, 0, 0);
        }
        if (found != NULL)
        {
            if (stealExisting == 0)
            {
                return;
            }
            sndFXKeyOff(found->handle);
            found->handle = (u32)-1;
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
            if (stealExisting != 0 || (int)gSfxObjectChannelMatchCount == 3)
            {
                sndFXKeyOff(found->handle);
                found->handle = (u32)-1;
            }
        }
    }
    ch = Sfx_AllocObjectChannel(outSfxId, vol, pitch, 0x40, globalCtrlDisabled);
    if (ch == NULL)
    {
        return;
    }
    ch->sfxId = sfxId;
    ch->channelMask = channelMask;
    ch->object = obj;
    if (pos != NULL)
    {
        ch->nearDistance = nearDist;
        ch->farDistance = farDist;
        ch->hasPosition = 1;
        {
            int t = 0;
            if (tracksObj != 0 && channelMask != 0)
            {
                t = 1;
            }
            ch->tracksObjectPosition = t;
        }
        ch->pos.x = pos->x;
        ch->pos.y = pos->y;
        ch->pos.z = pos->z;
        Sfx_UpdateObjectChannel3D(ch);
    }
    else
    {
        ch->volume = 0x7f;
    }
}

int Sfx_ResolveObjectSfxId(GameObject** object, u16* sfxId)
{
    switch (*sfxId)
    {
    case 0x170:
    case 0xca:
    case 0x109:
        *sfxId = 0x409;
    case 0x409:
        *object = NULL;
        break;
    case 0x7e:
    case 0x487:
        *object = NULL;
        break;
    case 0x420:
        Music_Trigger(MUSICTRIG_TTH_Fight, 0);
        Music_Trigger(MUSICTRIG_TTH_Fight, 1);
        return 0;
    case 0x38c:
        return !(gAudioActiveChannelMask & 4);
    case 0x0:
        return 0;
    }
    return 1;
}

int Sfx_ReadTriggerParams(SfxTriggerFull* trigger, u16* outSfxId, u8* outVol, f32* outF6, f32* outF7, f32* outF8,
                          int* outI9, int* outI10, int* outI11)
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
            *outF6 = (f32)(u32)trigger->pitchBase;
        }
    }
    *outF7 = (f32)(u32)trigger->nearDistanceRaw;
    *outF8 = (f32)(u32)trigger->farDistanceRaw;
    *outI9 = gSfxTriggerExtraTable[trigger->e_tableIdx];
    *outI10 = trigger->e_bit0;
    *outI11 = trigger->e_bit3;
    return 1;
}

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

SfxObjectChannel* Sfx_AllocObjectChannel(u16 fxId, u8 volume, double pitch, u8 pan,
                                         int globalCtrlDisabled)
{
    SfxObjectChannel* ch;
    u32 handle;

    if ((int)audioIsChannelUnavailable(4) != 0)
    {
        return 0;
    }

    ch = Sfx_FindFreeObjectChannel();
    if (ch == NULL)
    {
        return 0;
    }

    handle = sndFXStartEx(fxId, volume, pan, 0);
    if (handle != (u32)-1)
    {
        if (gSfxGlobalReverbLevel != 0 && globalCtrlDisabled == 0)
        {
            sndFXCtrl(handle, MCMD_CTRL_REVERB, gSfxGlobalReverbLevel);
        }

        ch->object = 0;
        ch->channelMask = 0;
        ch->paused = 0;
        ch->hasPosition = 0;
        ch->tracksObjectPosition = 0;
        ch->handle = handle;
        {
            f32 fz = 0.0f;
            ch->pos.x = fz;
            ch->pos.y = fz;
            ch->pos.z = fz;
        }
        ch->fxId = fxId;
        ch->volume = 0x64;
        ch->nearDistance = 100.0f;
        ch->farDistance = 640.0f;
        ch->globalCtrlDisabled = globalCtrlDisabled;

        ch->age = gSfxObjectChannelAge++;
        return ch;
    }
    ch->handle = (u32)-1;
    return 0;
}

void Sfx_UpdateObjectChannel3D(SfxObjectChannel* objectChannel)
{
    Camera* slot;
    int level;
    f32 dist;
    f32 near;
    f32 far;
    f32 volf;
    Vec delta;

    slot = Camera_GetCurrent();
    if (slot == NULL || objectChannel == NULL) {
        return;
    }
    if (!objectChannel->hasPosition) {
        return;
    }
    volf = (f32)(u32)objectChannel->volume;
    level = volf;
    near = objectChannel->nearDistance;
    far = objectChannel->farDistance;
    dist = Sfx_GetListenerRelativeDistance(&objectChannel->pos, &delta);
    if (dist > 1.1f * far) {
        sndFXKeyOff(objectChannel->handle);
        objectChannel->handle = (u32)-1;
        return;
    }
    Sfx_RotateVectorByAngles(0, 0, -slot->worldRoll, &delta);
    Sfx_RotateVectorByAngles(slot->yaw, 0, 0, &delta);
    Sfx_RotateVectorByAngles(0, -slot->worldPitch, 0, &delta);
    if (dist > 0.01f) {
        f32 scale;
        int pan;
        int fx;

        if (dist < near) {
            level = (int)(f64)volf;
        } else if (dist > far) {
            level = 1;
        } else {
            level = (int)(volf * (1.0f - (dist - near) / (far - near)));
            if (level < 1) {
                level = 1;
            } else if ((f32)level > volf) {
                level = (int)(f64)volf;
            }
        }
        scale = 1.2f / dist;
        delta.x *= scale;
        delta.y *= scale;
        delta.z *= scale;
        pan = (int)(64.0f + 63.0f * delta.x);
        if (pan > 0x7f)
        {
            pan = 0x7f;
        }
        else if (pan < 0)
        {
            pan = 0;
        }
        fx = (int)(64.0f + 63.0f * delta.z);
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

static void Sfx_RotateVectorByAngles(s16 angX, s16 angY, s16 angZ, Vec* v)
{
    f32 ra;
    f32 x = v->x;
    f32 y = v->y;
    f32 z = v->z;
    f32 ca;
    f32 rb;
    f32 cb;
    f32 rc;
    f32 cc;
    f32 sa;
    f32 sb;
    f32 sc;
    f32 t0, t1, A, B, p;

    ra = 3.1415927f * angX / 32768.0f;
    ca = mathSinf(ra);
    rb = 3.1415927f * angY / 32768.0f;
    cb = mathSinf(rb);
    rc = 3.1415927f * angZ / 32768.0f;
    cc = mathSinf(rc);
    sa = mathCosf(ra);
    sb = mathCosf(rb);
    sc = mathCosf(rc);

    t0 = x * ca;
    t1 = z * ca;
    A = x * sa;
    p = z * sa;
    A += t1;
    p -= t0;
    t0 = y * cb;
    t1 = p * cb;
    B = y * sb;
    p *= sb;
    B -= t1;
    p += t0;
    t0 = A * cc;
    t1 = B * cc;
    A *= sc;
    B *= sc;
    A -= t1;
    B += t0;

    v->x = A;
    v->y = B;
    v->z = p;
}

static f32 Sfx_GetListenerRelativeDistance(Vec* soundPos, Vec* outDelta)
{
    Vec v;
    f32 t;
    double t2;
    Vec* listener;
    GameObject* player = Obj_GetPlayerObject();
    Camera* slot = Camera_GetCurrent();
    int seqNo = getCurSeqNo();

    if (player != NULL && seqNo == 0)
    {
        listener = &player->anim.worldPos;
    }
    else if (slot != NULL)
    {
        if (player != NULL)
        {
            PSVECSubtract(&slot->worldPosition, &player->anim.worldPos, &v);
            t = (PSVECMag(&v) - 150.0f) / 250.0f;
            if (1.0 < (t > 0.0 ? t : 0.0))
            {
                t2 = 1.0;
            }
            else
            {
                t2 = (t > 0.0 ? t : 0.0);
            }
            PSVECScale(&v, &v, t2);
            PSVECAdd(&player->anim.worldPos, &v, &v);
            listener = &v;
        }
        else
        {
            listener = &slot->worldPosition;
        }
    }
    else
    {
        return 0.0f;
    }
    PSVECSubtract(listener, soundPos, outDelta);
    return PSVECMag(outDelta);
}

SfxObjectChannel* Sfx_FindObjectChannel(GameObject* obj, u32 channel, u16 sfxId, s32 mode)
{
    SfxObjectChannel* objectChannel = gSfxObjectChannels;
    SfxObjectChannel* bestChannel = NULL;
    u64 bestAge = mode == 2 ? 0 : -1;
    int channelMask;
    s32 i;

    gSfxObjectChannelMatchCount = 0;
    channelMask = (u8)channel;

    for (i = SFX_OBJECT_CHANNEL_COUNT; i != 0; i--)
    {
        if (objectChannel->handle != (u32)-1 && (obj == 0 || objectChannel->object == obj) &&
            ((u8)channel == 0 || (objectChannel->channelMask & channelMask) != 0) &&
            (sfxId == 0 || objectChannel->sfxId == sfxId))
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

            if (mode != 3 && (int)gSfxObjectChannelMatchCount == 3)
            {
                return bestChannel;
            }
        }
        objectChannel++;
    }

    return bestChannel;
}


SfxTriggerCacheEntry gSfxTriggerLookupCache[16] = {
    {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0},
    {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0}, {0xFFFF, 0},
};
