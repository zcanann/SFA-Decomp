#include "main/audio/snd3d.h"
#include "main/audio/synth_channel_scale.h"
#include "main/audio/synth_job_init.h"
#include "main/audio/vsample_alloc.h"
#include "main/audio/synth_virtual_sample.h"
#include "main/audio/synth_delay.h"
extern void dataInit(int p1, void* p2);
extern void synthInit(u32 sampleRate, u32 voiceCount);
extern int synthFXStart(u32 fxId, u32 volume, u32 pan, u8 studio, u32 studioAux);
extern int sndFXCheck(u32 id);
#define S3D_UNLINK_EMITTER(emitter)                         \
    do {                                                    \
        if ((emitter)->next != (Snd3DEmitter *)0x0) {       \
            (emitter)->next->prev = (emitter)->prev;        \
        }                                                   \
        if ((emitter)->prev != (Snd3DEmitter *)0x0) {       \
            (emitter)->prev->next = (emitter)->next;        \
        } else {                                            \
            s3dEmitterRoot = (emitter)->next;               \
        }                                                   \
    } while (0)

extern u8 lbl_803BD150[];
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
extern u8 lbl_803DE36A;
extern u8 lbl_803DE36B;
extern u8 lbl_803DE36C;
extern u8 lbl_803DE36D;
extern f32 lbl_803E7880;
extern f32 lbl_803E78A4;
extern f32 lbl_803E78C4;

void s3dHandle(void)
{
    Snd3DEmitter* emitter;
    Snd3DEmitter* next;
    SndSpatialEntry* entry;
    u32 flags;
    f32 ageLimit;
    f32 ageStep;
    f32 zeroDist;
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
    zeroDist = lbl_803E7880;
    ageStep = lbl_803E78C4;
    ageLimit = lbl_803E78A4;

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
                if ((zeroDist == distance) &&
                    ((flags & S3D_EMITTER_FLAG_STOP_AT_ORIGIN) != 0))
                {
                    emitter->flags |= S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                    emitter->flags &= ~S3D_EMITTER_FLAG_PLAYING;
                }
                else if ((zeroDist == distance) &&
                    ((flags & S3D_EMITTER_FLAG_REMOVE_AT_ORIGIN) != 0))
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
                        if ((emitter->handle = synthFXStart(emitter->fxId, S3D_DEFAULT_FX_VOLUME,
                                                            S3D_DEFAULT_FX_PAN,
                                                            entry != (SndSpatialEntry*)0x0
                                                                ? entry->assignedVoice
                                                                : emitter->studio,
                                                            (flags & S3D_EMITTER_FLAG_USE_AUX_STUDIO) != 0)) !=
                            S3D_INVALID_FX_HANDLE)
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
                if ((zeroDist == distance) &&
                    ((emitter->flags & S3D_EMITTER_FLAG_STOP_AT_ORIGIN) != 0))
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
                emitter->age += ageStep;
                if (emitter->age >= ageLimit)
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
                (zeroDist != distance))
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
 *
 * EN v1.0 Address: 0x80280BD8
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80280FFC
 * EN v1.1 Size: 68b
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
 *
 * EN v1.1 Address: 0x80281040
 */
void s3dExit(void)
{
}

/*
 * Sound init: clamps voice/stream counts, calls hwInit, then walks
 * a chain of subsystem inits if hwInit succeeded; sets the
 * gSynthInitialized flag last.
 *
 * EN v1.0 Address: 0x80280BDC
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80281044
 * EN v1.1 Size: 280b
 */
int sndInit(u8 voiceCount, u8 streamCount, u8 unk5, u8 stereo, u32 flags, void* data)
{
    u32 sampleRate;
    u32 sampleRatePad[3];
    int result;

    gSynthInitialized = 0;
    if (voiceCount <= SND_MAX_VOICES)
    {
        lbl_803BD150[0x210] = voiceCount;
    }
    else
    {
        lbl_803BD150[0x210] = SND_MAX_VOICES;
    }
    if (stereo <= SND_MAX_STUDIOS)
    {
        lbl_803BD150[0x213] = stereo;
    }
    else
    {
        lbl_803BD150[0x213] = SND_MAX_STUDIOS;
    }
    lbl_803BD150[0x211] = streamCount;
    lbl_803BD150[0x212] = unk5;
    (void)sampleRatePad;
    sampleRate = SND_DEFAULT_SAMPLE_RATE;
    result = hwInit(&sampleRate, lbl_803BD150[0x210], lbl_803BD150[0x213], flags);
    if (result == 0)
    {
        u8 voiceCountSnapshot = lbl_803BD150[0x210];
        synthResetLoadedGroupCount();
        dataInit(0, data);
        fn_8026F30C();
        synthIdleWaitActive = 0;
        synthInit(SND_DEFAULT_SAMPLE_RATE, voiceCountSnapshot);
        synthInitJobTable();
        synthInitVirtualSampleTable();
        s3dInit(flags);
        gSynthInitialized = 1;
        result = 0;
    }
    return result;
}
