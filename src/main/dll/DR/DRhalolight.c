#include "main/dll/DR/DRhalolight.h"
#include "main/game_object.h"
#include "main/objhits_types.h"
#include "main/dll/BW/BWalphaanim.h"

/*
 * --INFO--
 *
 * Function: SnowBike_hitDetect
 * EN v1.0 Address: 0x801ECF94
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x801ED20C
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void fn_801EB940(int obj, u8 *state);
extern f32 PSVECMag(f32 *v);
extern void doRumble(f32 f);
extern int arrayIndexOf(s16 *arr, int n, int value);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int ch);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void Sfx_SetObjectSfxVolume(int obj, int sfx, u8 vol, f32 v);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 f);
extern void OSReport(char *fmt, ...);
extern void Matrix_TransformPoint(f32 *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern s16 lbl_8032855C[];
extern char lbl_803DC0E4;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5B28;
extern f32 lbl_803E5B88;
extern f32 lbl_803E5B8C;
extern f32 lbl_803E5BA4;
extern f32 lbl_803E5BBC;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C4C;

typedef struct {
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} HaloSnowBikeFlags;

void SnowBike_hitDetect(int obj)
{
    SnowBikeState *state;
    u8 *other;
    int vol;
    f32 mag;
    f32 k;
    f32 k2;
    f32 v;
    f32 c;
    f32 lim;
    f32 dummy;

    state = ((GameObject *)obj)->extra;
    other = *(u8 **)(*(int *)&((GameObject *)obj)->anim.hitReactState);
    if (((GameObject *)obj)->pendingParentObj != NULL) {
        return;
    }
    if (state->riderMode == 2) {
        fn_801EB940(obj, (u8 *)state);
        state->unk41C = ((GameObject *)obj)->anim.rotY;
        state->unk41E = ((GameObject *)obj)->anim.rotZ;
        ((GameObject *)obj)->anim.rotY = (f32)((GameObject *)obj)->anim.rotY + state->haloPitchDrift;
        ((GameObject *)obj)->anim.rotZ = (f32)((GameObject *)obj)->anim.rotZ + ((f32)state->unk410 + state->unk598);
    }
    if (state->unk3D9 == 4 || state->unk3D6 != 0) {
        ((GameObject *)obj)->anim.velocityY = oneOverTimeDelta * (((GameObject *)obj)->anim.localPosY - ((GameObject *)obj)->anim.previousLocalPosY);
        state->unk498 = ((GameObject *)obj)->anim.velocityY;
    }
    if (state->unk3D6 == 0) {
        if (((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags & 8) != 0
            && arrayIndexOf(lbl_8032855C, 10, *(s16 *)(other + 0x46)) == -1) {
        } else {
            if (*(void **)&state->unk42C == NULL) {
                goto clamp;
            }
            if (!(state->unk3E0 <= lbl_803E5AEC)) {
                goto clamp;
            }
        }
    }
    mag = PSVECMag((f32 *)(obj + 0x24));
    if (mag > lbl_803E5AEC) {
        if (!((HaloSnowBikeFlags *)&state->flags428)->b02) {
            doRumble(lbl_803E5BC4 * mag);
        }
        state->unk430 = state->unk430 * lbl_803E5BBC;
        if (((GameObject *)obj)->anim.seqId == 114 || ((GameObject *)obj)->anim.seqId == 908) {
            vol = (int)(lbl_803E5C4C * mag);
            if (vol > 80) {
                vol = 80;
            } else if (vol < 30) {
                vol = 30;
            }
            if (Sfx_IsPlayingFromObjectChannel(obj, 32) == 0) {
                Sfx_PlayFromObject(obj, 956);
                Sfx_SetObjectSfxVolume(obj, 956, vol, lbl_803E5B28);
            }
        }
    }
    if (!((HaloSnowBikeFlags *)&state->flags428)->b02 && mag > lbl_803E5BC4) {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(mag * lbl_803E5AF8);
    }
    if (*(void **)&state->unk42C != NULL) {
        k = lbl_803E5C00;
        OSReport(&lbl_803DC0E4, mag);
        if (*(s16 *)(state->unk42C + 0x46) == 909
            || *(s16 *)(state->unk42C + 0x46) == 910
            || *(s16 *)(state->unk42C + 0x46) == 1236) {
            k = lbl_803E5B88;
        }
        ((GameObject *)obj)->anim.velocityX = k * (oneOverTimeDelta * (((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX));
        ((GameObject *)obj)->anim.velocityZ = k * (oneOverTimeDelta * (((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ));
    } else {
        k2 = lbl_803E5B88;
        ((GameObject *)obj)->anim.velocityX = k2 * (oneOverTimeDelta * (((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX));
        ((GameObject *)obj)->anim.velocityZ = k2 * (oneOverTimeDelta * (((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ));
    }
    Matrix_TransformPoint((f32 *)((u8 *)state + 0x12c), ((GameObject *)obj)->anim.velocityX, lbl_803E5AE8, ((GameObject *)obj)->anim.velocityZ,
                          &state->unk494, &dummy, &state->unk49C);
clamp:
    {
        f32 lim;
        f32 v = state->unk494;
        f32 c;
        lim = state->unk47C;
        if (v < -lim) {
            c = -lim;
        } else if (v > lim) {
            c = lim;
        } else {
            c = v;
        }
        state->unk494 = c;
    }
    if (state->unk494 < lbl_803E5B8C && state->unk494 > lbl_803E5BA4) {
        state->unk494 = lbl_803E5AE8;
    }
    v = state->unk498;
    lim = state->unk480;
    if (v < -lim) {
        c = -lim;
    } else if (v > lbl_803E5AEC) {
        c = lbl_803E5AEC;
    } else {
        c = v;
    }
    state->unk498 = c;
    if (state->unk498 < lbl_803E5B8C && state->unk498 > lbl_803E5BA4) {
        state->unk498 = lbl_803E5AE8;
    }
    {
        f32 lim;
        f32 v = state->unk49C;
        f32 c;
        lim = state->unk484;
        if (v < -lim) {
            c = -lim;
        } else if (v > lim) {
            c = lim;
        } else {
            c = v;
        }
        state->unk49C = c;
    }
    if (state->unk49C < lbl_803E5B8C && state->unk49C > lbl_803E5BA4) {
        state->unk49C = lbl_803E5AE8;
    }
    state->unk16C = ((GameObject *)obj)->anim.localPosX;
    state->unk170 = ((GameObject *)obj)->anim.localPosY;
    state->unk174 = ((GameObject *)obj)->anim.localPosZ;
    state->unk42C = 0;
}
