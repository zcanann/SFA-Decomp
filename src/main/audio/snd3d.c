#include "main/audio/snd3d.h"

#pragma exceptions on
#include "main/audio/synth_channel_scale.h"
#include "main/audio/synth_job_init.h"
#include "main/audio/vsample_alloc.h"
#include "main/audio/synth_virtual_sample.h"
#include "main/audio/synth_control.h"
#include "main/audio/snd_synth_api.h"
#include "main/audio/synth_voice.h"
#include "main/audio/synth_config.h"

#define S3D_UNLINK_EMITTER(emitter)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((emitter)->next != (Snd3DEmitter*)0x0)                                                                     \
        {                                                                                                              \
            (emitter)->next->prev = (emitter)->prev;                                                                   \
        }                                                                                                              \
        if ((emitter)->prev != (Snd3DEmitter*)0x0)                                                                     \
        {                                                                                                              \
            (emitter)->prev->next = (emitter)->next;                                                                   \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            s3dEmitterRoot = (emitter)->next;                                                                          \
        }                                                                                                              \
    } while (0)

extern u8 gSynthInitialized;
extern u8 synthIdleWaitActive;
extern u8 s3dCallCnt;
extern Snd3DEmitter* s3dEmitterRoot;
extern SndSpatialListener* s3dListenerRoot;
extern SndSpatialEntry* s3dRoomRoot;
extern SndStudioInputLink* s3dDoorRoot;
extern u32 snd_used_studios;
extern u8 snd_base_studio;
extern u8 snd_max_studios;
extern u32 synthSendKeyOff(u32 handle);
extern u8 lbl_803DE36A;
extern u8 lbl_803DE36B;
extern u8 lbl_803DE36C;
extern u8 lbl_803DE36D;
extern void dataInit(int p1, void* p2);

void s3dHandle(void)
{
    Snd3DEmitter* emitter;
    Snd3DEmitter* next;
    SndSpatialEntry* entry;
    u32 flags;
    f32 distance;
    f32 azimuth;
    f32 pitch;
    f32 frontBack;
    f32 pan;

    if (s3dCallCnt != 0)
    {
        s3dCallCnt--;
        return;
    }

    s3dCallCnt = S3D_UPDATE_SKIP_TICKS;
    lbl_803DE36B = 0;
    lbl_803DE36C = 0;
    lbl_803DE36D = 0;
    emitter = s3dEmitterRoot;

    for (; emitter != (Snd3DEmitter*)0x0; emitter = next)
    {
        next = emitter->next;

        if ((emitter->flags & S3D_EMITTER_FLAG_REMOVE) != 0)
        {
            S3D_UNLINK_EMITTER(emitter);
            emitter->flags &= 0xffff;
            if (emitter->handle != S3D_INVALID_FX_HANDLE)
            {
                synthSendKeyOff(emitter->handle);
            }
            continue;
        }

        if ((emitter->flags & (S3D_EMITTER_FLAG_PLAYING | S3D_EMITTER_FLAG_POSITIONAL)) != 0)
        {
            s3dCalcEmitter(emitter, &distance, &pan, &azimuth, &pitch, &frontBack);
        }

        flags = emitter->flags;
        if ((flags & S3D_EMITTER_FLAG_WAITING_FOR_ROOM) == 0)
        {
            if ((flags & S3D_EMITTER_FLAG_PLAYING) != 0)
            {
                if ((0.0f == distance) && ((flags & S3D_EMITTER_FLAG_STOP_AT_ORIGIN) != 0))
                {
                    emitter->flags |= S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                    emitter->flags &= ~S3D_EMITTER_FLAG_PLAYING;
                }
                else if ((0.0f == distance) && ((flags & S3D_EMITTER_FLAG_REMOVE_AT_ORIGIN) != 0))
                {
                    S3D_UNLINK_EMITTER(emitter);
                    emitter->flags &= 0xffff;
                    if (emitter->handle != S3D_INVALID_FX_HANDLE)
                    {
                        synthSendKeyOff(emitter->handle);
                    }
                    continue;
                }
                else if ((flags & S3D_EMITTER_FLAG_POSITIONAL) != 0)
                {
                    if ((u32)s3dInsertActiveEmitter(emitter, distance, azimuth, pitch, frontBack, pan) != 0)
                    {
                        continue;
                    }
                }
                else
                {
                    entry = emitter->entry;
                    if ((entry == (SndSpatialEntry*)0x0) || (entry->assignedVoice != 0xff))
                    {
                        if ((emitter->handle =
                                 synthFXStart(emitter->fxId, S3D_DEFAULT_FX_VOLUME, S3D_DEFAULT_FX_PAN,
                                              entry != (SndSpatialEntry*)0x0 ? entry->assignedVoice : emitter->studio,
                                              (flags & S3D_EMITTER_FLAG_USE_AUX_STUDIO) != 0)) != S3D_INVALID_FX_HANDLE)
                        {
                            goto update_voice;
                        }
                    }
                    if ((emitter->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) != 0)
                    {
                        continue;
                    }
                    emitter->flags |= S3D_EMITTER_FLAG_REMOVE;
                    emitter->flags &= ~S3D_EMITTER_FLAG_PLAYING;
                }
            }
            else
            {
                if ((emitter->handle = sndFXCheck(emitter->handle)) == S3D_INVALID_FX_HANDLE)
                {
                    if ((emitter->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) != 0)
                    {
                        emitter->flags |= S3D_EMITTER_FLAG_PLAYING;
                    }
                    else
                    {
                        emitter->flags |= S3D_EMITTER_FLAG_REMOVE;
                    }
                }
            }

        update_voice:
            if (emitter->handle != S3D_INVALID_FX_HANDLE)
            {
                if ((emitter->flags & S3D_EMITTER_FLAG_POSITIONAL) != 0)
                {
                    s3dInsertSortedEmitter(emitter, distance);
                }
                if ((0.0f == distance) && ((emitter->flags & S3D_EMITTER_FLAG_STOP_AT_ORIGIN) != 0))
                {
                    synthSendKeyOff(emitter->handle);
                    emitter->handle = S3D_INVALID_FX_HANDLE;
                    if ((emitter->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) != 0)
                    {
                        emitter->flags |= S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                    }
                    else
                    {
                        emitter->flags |= S3D_EMITTER_FLAG_REMOVE;
                    }
                }
                else
                {
                    s3dApplyEmitterControls(emitter, distance, azimuth, pitch, frontBack, pan);
                }
            }
            if ((emitter->flags & S3D_EMITTER_FLAG_AGE_OUT) != 0)
            {
                emitter->age += 0.3f;
                if (emitter->age >= 1.0f)
                {
                    emitter->flags &= ~S3D_EMITTER_FLAG_AGE_OUT;
                }
            }
        }
        else
        {
            entry = emitter->entry;
            if (((entry == (SndSpatialEntry*)0x0) ||
                 ((entry != (SndSpatialEntry*)0x0) && (entry->assignedVoice != 0xff))) &&
                (0.0f != distance))
            {
                emitter->flags &= ~S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                emitter->flags |= S3D_EMITTER_FLAG_PLAYING;
            }
        }
    }

    s3dStartQueuedEmitters();
    s3dAllocateRoomStudios();
    s3dUpdateDoorStudioInputs();
}

/*
 * Reset 3D sound bookkeeping and store a stereo flag.
 */
#pragma dont_inline on
void s3dInit(u32 flags)
{
    u8 stereo = (flags & S3D_INIT_STEREO_FLAG) != 0;
    s3dEmitterRoot = 0;
    s3dListenerRoot = 0;
    s3dRoomRoot = 0;
    s3dDoorRoot = 0;
    snd_used_studios = 0;
    snd_base_studio = S3D_BASE_STUDIO;
    snd_max_studios = S3D_MAX_STUDIOS;
    s3dCallCnt = 0;
    lbl_803DE36A = stereo;
}
#pragma dont_inline reset

/*
 * Empty stub.
 */
void s3dExit(void)
{
}

/*
 * Sound init: clamps voice/stream counts, calls hwInit, then walks
 * a chain of subsystem inits if hwInit succeeded; sets the
 * gSynthInitialized flag last.
 */
int sndInit(u8 voiceCount, u8 streamCount, u8 unk5, u8 stereo, u32 flags, void* data)
{
    u32 sampleRate;
    u32 sampleRatePad[3];
    int result;

    gSynthInitialized = 0;
    if (voiceCount <= SND_MAX_VOICES)
    {
        SYNTH_CONFIGURATION->voiceCount = voiceCount;
    }
    else
    {
        SYNTH_CONFIGURATION->voiceCount = SND_MAX_VOICES;
    }
    if (stereo <= SND_MAX_STUDIOS)
    {
        SYNTH_CONFIGURATION->studioCount = stereo;
    }
    else
    {
        SYNTH_CONFIGURATION->studioCount = SND_MAX_STUDIOS;
    }
    SYNTH_CONFIGURATION->musicVoiceCount = streamCount;
    SYNTH_CONFIGURATION->fxVoiceCount = unk5;
    (void)sampleRatePad;
    sampleRate = SND_DEFAULT_SAMPLE_RATE;
    result = hwInit(&sampleRate, SYNTH_CONFIGURATION->voiceCount, SYNTH_CONFIGURATION->studioCount, flags);
    if (result == 0)
    {
        u8 voiceCountSnapshot = SYNTH_CONFIGURATION->voiceCount;
        synthResetLoadedGroupCount();
        dataInit(0, data);
        fn_8026F30C();
        synthIdleWaitActive = 0;
        synthInit(SND_DEFAULT_SAMPLE_RATE, voiceCountSnapshot);
        streamInit();
        synthInitVirtualSampleTable();
        s3dInit(flags);
        gSynthInitialized = 1;
        result = 0;
    }
    return result;
}
