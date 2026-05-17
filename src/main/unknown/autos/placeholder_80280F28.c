#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80280F28.h"

extern int hwInit(u32 *sampleRate, u8 voiceCount, u8 maxStudios, u32 flags);
extern void dataInit(int p1, void *p2);
extern void fn_8026F30C(void);
extern void synthInit(u32 sampleRate, u32 voiceCount);
extern void synthInitJobTable(void);
extern void synthInitVirtualSampleTable(void);
extern void synthResetLoadedGroupCount(void);
extern void s3dInit(u32 flags);
extern u32 synthSendKeyOff(u32 handle);
extern int synthFXStart(u32 fxId, u32 volume, u32 pan, u32 studio, u8 studioAux);
extern int sndFXCheck(u32 id);
extern void fn_802800C0(void *emitter, f32 *distance, f32 *arg1, f32 *arg2, f32 *arg3, f32 *arg4);
extern void fn_802805A4(void *emitter, f32 distance, f32 arg1, f32 arg2, f32 arg3, f32 arg4);
extern int fn_802807C4(void *emitter, f32 distance);
extern int fn_802808D8(void *emitter, f32 distance, f32 arg1, f32 arg2, f32 arg3, f32 arg4);
extern void audioFn_80280a08(void);
extern void fn_8027FB08(void);
extern void fn_8027FEE4(void);

typedef struct SndSpatialEntry {
    struct SndSpatialEntry *next;
    u8 pad04[0x18];
    s8 assignedVoice;
} SndSpatialEntry;

typedef struct Snd3DEmitter {
    struct Snd3DEmitter *next;
    struct Snd3DEmitter *prev;
    SndSpatialEntry *entry;
    u8 pad0c[4];
    u32 flags;
    u8 pad14[0x3c - 0x14];
    u32 handle;
    u8 pad40[4];
    u16 fxId;
    u8 studio;
    u8 pad47[0x4c - 0x47];
    f32 age;
} Snd3DEmitter;

#define S3D_EMITTER_FLAG_POSITIONAL 0x00000001
#define S3D_EMITTER_FLAG_RESTART_ON_STOP 0x00000002
#define S3D_EMITTER_FLAG_STOP_AT_ORIGIN 0x00000004
#define S3D_EMITTER_FLAG_USE_AUX_STUDIO 0x00000010
#define S3D_EMITTER_FLAG_REMOVE_AT_ORIGIN 0x00000040
#define S3D_EMITTER_FLAG_PLAYING 0x00020000
#define S3D_EMITTER_FLAG_REMOVE 0x00040000
#define S3D_EMITTER_FLAG_WAITING_FOR_ROOM 0x00080000
#define S3D_EMITTER_FLAG_AGE_OUT 0x00100000
#define S3D_INVALID_FX_HANDLE 0xffffffff

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
extern Snd3DEmitter *s3dEmitterRoot;
extern void *s3dListenerRoot;
extern void *s3dRoomRoot;
extern void *s3dDoorRoot;
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

#pragma dont_inline on
void s3dHandle(void)
{
    Snd3DEmitter *emitter;
    Snd3DEmitter *next;
    SndSpatialEntry *entry;
    u32 flags;
    f32 distance;
    f32 arg1;
    f32 arg2;
    f32 arg3;
    f32 arg4;

    if (s3dCallCnt != 0) {
        s3dCallCnt--;
        return;
    }

    lbl_803DE36B = 0;
    s3dCallCnt = 3;
    lbl_803DE36C = 0;
    lbl_803DE36D = 0;

    for (emitter = s3dEmitterRoot; emitter != (Snd3DEmitter *)0x0; emitter = next) {
        next = emitter->next;
        flags = emitter->flags;

        if ((flags & S3D_EMITTER_FLAG_REMOVE) != 0) {
            S3D_UNLINK_EMITTER(emitter);
            emitter->flags &= 0xffff;
            if (emitter->handle != S3D_INVALID_FX_HANDLE) {
                synthSendKeyOff(emitter->handle);
            }
            continue;
        }

        if ((flags & (S3D_EMITTER_FLAG_PLAYING | S3D_EMITTER_FLAG_POSITIONAL)) != 0) {
            fn_802800C0(emitter, &distance, &arg1, &arg2, &arg3, &arg4);
        }

        flags = emitter->flags;
        if ((flags & S3D_EMITTER_FLAG_WAITING_FOR_ROOM) == 0) {
            if ((flags & S3D_EMITTER_FLAG_PLAYING) == 0) {
                emitter->handle = sndFXCheck(emitter->handle);
                if (emitter->handle == S3D_INVALID_FX_HANDLE) {
                    if ((emitter->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) == 0) {
                        emitter->flags |= S3D_EMITTER_FLAG_REMOVE;
                    } else {
                        emitter->flags |= S3D_EMITTER_FLAG_PLAYING;
                    }
                }
            } else if ((distance == lbl_803E7880) &&
                       ((flags & S3D_EMITTER_FLAG_STOP_AT_ORIGIN) != 0)) {
                emitter->flags |= S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                emitter->flags &= ~S3D_EMITTER_FLAG_PLAYING;
            } else if ((distance == lbl_803E7880) &&
                       ((flags & S3D_EMITTER_FLAG_REMOVE_AT_ORIGIN) != 0)) {
                S3D_UNLINK_EMITTER(emitter);
                emitter->flags &= 0xffff;
                if (emitter->handle != S3D_INVALID_FX_HANDLE) {
                    synthSendKeyOff(emitter->handle);
                }
                continue;
            } else if ((flags & S3D_EMITTER_FLAG_POSITIONAL) != 0) {
                if (fn_802808D8(emitter, distance, arg1, arg2, arg3, arg4) != 0) {
                    continue;
                }
            } else {
                entry = emitter->entry;
                if ((entry == (SndSpatialEntry *)0x0) || (entry->assignedVoice != -1)) {
                    u8 studio;

                    if (entry == (SndSpatialEntry *)0x0) {
                        studio = emitter->studio;
                    } else {
                        studio = entry->assignedVoice;
                    }
                    emitter->handle = synthFXStart(emitter->fxId, 0x7f, 0x40, studio,
                                                   (emitter->flags & S3D_EMITTER_FLAG_USE_AUX_STUDIO) != 0);
                    if (emitter->handle != S3D_INVALID_FX_HANDLE) {
                        goto update_voice;
                    }
                }
                if ((emitter->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) == 0) {
                    emitter->flags |= S3D_EMITTER_FLAG_REMOVE;
                    emitter->flags &= ~S3D_EMITTER_FLAG_PLAYING;
                }
            }

update_voice:
            if (emitter->handle != S3D_INVALID_FX_HANDLE) {
                if ((emitter->flags & S3D_EMITTER_FLAG_POSITIONAL) != 0) {
                    fn_802807C4(emitter, distance);
                }
                if ((distance == lbl_803E7880) &&
                    ((emitter->flags & S3D_EMITTER_FLAG_STOP_AT_ORIGIN) != 0)) {
                    synthSendKeyOff(emitter->handle);
                    emitter->handle = S3D_INVALID_FX_HANDLE;
                    if ((emitter->flags & S3D_EMITTER_FLAG_RESTART_ON_STOP) != 0) {
                        emitter->flags |= S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                    } else {
                        emitter->flags |= S3D_EMITTER_FLAG_REMOVE;
                    }
                } else {
                    fn_802805A4(emitter, distance, arg1, arg2, arg3, arg4);
                }
            }
            if ((emitter->flags & S3D_EMITTER_FLAG_AGE_OUT) != 0) {
                emitter->age += lbl_803E78C4;
                if (lbl_803E78A4 <= emitter->age) {
                    emitter->flags &= ~S3D_EMITTER_FLAG_AGE_OUT;
                }
            }
        } else {
            entry = emitter->entry;
            if (((entry == (SndSpatialEntry *)0x0) || (entry->assignedVoice != -1)) &&
                (distance != lbl_803E7880)) {
                emitter->flags &= ~S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                emitter->flags |= S3D_EMITTER_FLAG_PLAYING;
            }
        }
    }

    audioFn_80280a08();
    fn_8027FB08();
    fn_8027FEE4();
}
#pragma dont_inline reset

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
    u8 stereo = (flags & 0x2) != 0;
    s3dEmitterRoot = 0;
    s3dListenerRoot = 0;
    s3dRoomRoot = 0;
    s3dDoorRoot = 0;
    snd_used_studios = 0;
    snd_base_studio = 1;
    snd_max_studios = 3;
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
int sndInit(u8 voiceCount, u8 streamCount, u8 unk5, u8 stereo, u32 flags, void *data)
{
    u32 sampleRate[4];
    int result;

    gSynthInitialized = 0;
    if (voiceCount <= 0x40) {
        lbl_803BD150[0x210] = voiceCount;
    } else {
        lbl_803BD150[0x210] = 0x40;
    }
    if (stereo <= 0x8) {
        lbl_803BD150[0x213] = stereo;
    } else {
        lbl_803BD150[0x213] = 0x8;
    }
    lbl_803BD150[0x211] = streamCount;
    lbl_803BD150[0x212] = unk5;
    sampleRate[3] = 0x7d00;
    result = hwInit(&sampleRate[3], lbl_803BD150[0x210], lbl_803BD150[0x213], flags);
    if (result == 0) {
        u8 voiceCountSnapshot = lbl_803BD150[0x210];
        synthResetLoadedGroupCount();
        dataInit(0, data);
        fn_8026F30C();
        synthIdleWaitActive = 0;
        synthInit(0x7d00, voiceCountSnapshot);
        synthInitJobTable();
        synthInitVirtualSampleTable();
        s3dInit(flags);
        gSynthInitialized = 1;
        result = 0;
    }
    return result;
}
