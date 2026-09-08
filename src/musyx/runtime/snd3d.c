#include "musyx/snd3d.h"

#include "musyx/synth_channel_scale.h"
#include "musyx/synth_job_init.h"
#include "musyx/synth_virtual_sample.h"
#include "musyx/snd_groups.h"
#include "musyx/synth_control.h"
#include "musyx/snd_synth_api.h"
#include "musyx/synth_voice.h"
#include "musyx/synth_config.h"
#include "musyx/synth_delay.h"
#include "musyx/data_tables.h"
#include "musyx/snd_core.h"
#include "musyx/hw_init.h"

#define S3D_UNLINK_EMITTER(emitter)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((emitter)->next != (SND_EMITTER*)0x0)                                                                     \
        {                                                                                                              \
            (emitter)->next->prev = (emitter)->prev;                                                                   \
        }                                                                                                              \
        if ((emitter)->prev != (SND_EMITTER*)0x0)                                                                     \
        {                                                                                                              \
            (emitter)->prev->next = (emitter)->next;                                                                   \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            s3dEmitterRoot = (emitter)->next;                                                                          \
        }                                                                                                              \
    } while (0)

u8 runListNum;
u8 startListNumnum;
u8 startGroupNum;
u8 sSnd3dStereo;
u8 snd_max_studios;
u8 snd_base_studio;
u32 snd_used_studios;
SND_DOOR* s3dDoorRoot;
SND_ROOM* s3dRoomRoot;
SND_LISTENER* s3dListenerRoot;
SND_EMITTER* s3dEmitterRoot;
u8 s3dCallCnt;

void s3dHandle(void)
{
    SND_EMITTER* em;
    SND_EMITTER* next;
    SND_ROOM* entry;
    u32 flags;
    f32 vol;
    f32 xPan;
    f32 yPan;
    f32 zPan;
    f32 pitch;

    if (s3dCallCnt != 0)
    {
        s3dCallCnt--;
        return;
    }

    s3dCallCnt = S3D_UPDATE_SKIP_TICKS;
    startGroupNum = 0;
    startListNumnum = 0;
    runListNum = 0;
    em = s3dEmitterRoot;

    for (; em != (SND_EMITTER*)0x0; em = next)
    {
        next = em->next;

        if ((em->flags & S3D_EMITTER_FLAG_REMOVE) != 0)
        {
            S3D_UNLINK_EMITTER(em);
            em->flags &= 0xffff;
            if (em->vid != S3D_INVALID_FX_HANDLE)
            {
                synthSendKeyOff(em->vid);
            }
            continue;
        }

        if ((em->flags & (S3D_EMITTER_FLAG_PLAYING | S3D_EMITTER_FLAG_POSITIONAL)) != 0)
        {
            CalcEmitter(em, &vol, &pitch, &xPan, &yPan, &zPan);
        }

        flags = em->flags;
        if ((flags & S3D_EMITTER_FLAG_WAITING_FOR_ROOM) == 0)
        {
            if ((flags & S3D_EMITTER_FLAG_PLAYING) != 0)
            {
                if ((0.0f == vol) && ((flags & S3D_EMITTER_FLAG_STOP_AT_ORIGIN) != 0))
                {
                    em->flags |= S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                    em->flags &= ~S3D_EMITTER_FLAG_PLAYING;
                }
                else if ((0.0f == vol) && ((flags & S3D_EMITTER_FLAG_REMOVE_AT_ORIGIN) != 0))
                {
                    S3D_UNLINK_EMITTER(em);
                    em->flags &= 0xffff;
                    if (em->vid != S3D_INVALID_FX_HANDLE)
                    {
                        synthSendKeyOff(em->vid);
                    }
                    continue;
                }
                else if ((flags & S3D_EMITTER_FLAG_POSITIONAL) != 0)
                {
                    if ((u32)AddStartingEmitter(em, vol, xPan, yPan, zPan, pitch) != 0)
                    {
                        continue;
                    }
                }
                else
                {
                    entry = em->room;
                    if (((entry == (SND_ROOM*)0x0) || (entry->studio != 0xff)) &&
                        (em->vid =
                             synthFXStart(em->fxid, S3D_DEFAULT_FX_VOLUME, S3D_DEFAULT_FX_PAN,
                                          entry != (SND_ROOM*)0x0 ? entry->studio : em->studio,
                                          (flags & S3D_EMITTER_FLAG_USE_AUX_STUDIO) != 0)) != S3D_INVALID_FX_HANDLE)
                    {
                    }
                    else
                    {
                        if ((em->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) != 0)
                        {
                            continue;
                        }
                        em->flags |= S3D_EMITTER_FLAG_REMOVE;
                        em->flags &= ~S3D_EMITTER_FLAG_PLAYING;
                    }
                }
            }
            else
            {
                if ((em->vid = sndFXCheck(em->vid)) == S3D_INVALID_FX_HANDLE)
                {
                    if ((em->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) != 0)
                    {
                        em->flags |= S3D_EMITTER_FLAG_PLAYING;
                    }
                    else
                    {
                        em->flags |= S3D_EMITTER_FLAG_REMOVE;
                    }
                }
            }

            if (em->vid != S3D_INVALID_FX_HANDLE)
            {
                if ((em->flags & S3D_EMITTER_FLAG_POSITIONAL) != 0)
                {
                    AddRunningEmitter(em, vol);
                }
                if ((0.0f == vol) && ((em->flags & S3D_EMITTER_FLAG_STOP_AT_ORIGIN) != 0))
                {
                    synthSendKeyOff(em->vid);
                    em->vid = S3D_INVALID_FX_HANDLE;
                    if ((em->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) != 0)
                    {
                        em->flags |= S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                    }
                    else
                    {
                        em->flags |= S3D_EMITTER_FLAG_REMOVE;
                    }
                }
                else
                {
                    SetFXParameters(em, vol, xPan, yPan, zPan, pitch);
                }
            }
            if ((em->flags & S3D_EMITTER_FLAG_AGE_OUT) != 0)
            {
                em->fade += 0.3f;
                if (em->fade >= 1.0f)
                {
                    em->flags &= ~S3D_EMITTER_FLAG_AGE_OUT;
                }
            }
        }
        else
        {
            entry = em->room;
            if (((entry == (SND_ROOM*)0x0) ||
                 ((entry != (SND_ROOM*)0x0) && (entry->studio != 0xff))) &&
                (0.0f != vol))
            {
                em->flags &= ~S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                em->flags |= S3D_EMITTER_FLAG_PLAYING;
            }
        }
    }

    StartContinousEmitters();
    CheckRoomStatus();
    CheckDoorStatus();
}

/*
 * Reset 3D sound bookkeeping and store a stereo flag.
 */
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
    sSnd3dStereo = stereo;
}

/*
 * Empty stub.
 */
void s3dExit(void)
{
}

/*
 * Sound init: clamps voice/stream counts, calls hwInit, then walks
 * a chain of subsystem inits if hwInit succeeded; sets the
 * sndActive flag last.
 */
int sndInit(u8 voiceCount, u8 streamCount, u8 unk5, u8 stereo, u32 flags, u32 aramSize)
{
    u32 sampleRate;
    u32 sampleRatePad[3];
    int result;

    sndActive = 0;
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
        dataInitStack();
        dataInit(0, aramSize);
        seqInit();
        synthIdleWaitActive = 0;
        synthInit(SND_DEFAULT_SAMPLE_RATE, voiceCountSnapshot);
        streamInit();
        vsInit();
        s3dInit(flags);
        sndActive = 1;
        result = 0;
    }
    return result;
}
