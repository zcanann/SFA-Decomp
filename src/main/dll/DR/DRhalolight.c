#include "main/dll/DR/DRhalolight.h"

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

#pragma scheduling off
#pragma peephole off
void SnowBike_hitDetect(int obj)
{
    u8 *state;
    u8 *other;
    int vol;
    f32 mag;
    f32 k;
    f32 k2;
    f32 v;
    f32 c;
    f32 lim;
    f32 dummy;

    state = *(u8 **)(obj + 0xb8);
    other = *(u8 **)(*(int *)(obj + 0x54));
    if (*(void **)(obj + 0xc0) != NULL) {
        return;
    }
    if (*(s8 *)(state + 0x421) == 2) {
        fn_801EB940(obj, state);
        *(s16 *)(state + 0x41c) = *(s16 *)(obj + 2);
        *(s16 *)(state + 0x41e) = *(s16 *)(obj + 4);
        *(s16 *)(obj + 2) = (f32)*(s16 *)(obj + 2) + *(f32 *)(state + 0x594);
        *(s16 *)(obj + 4) = (f32)*(s16 *)(obj + 4) + ((f32)*(int *)(state + 0x410) + *(f32 *)(state + 0x598));
    }
    if (*(s8 *)(state + 0x3d9) == 4 || state[0x3d6] != 0) {
        *(f32 *)(obj + 0x28) = oneOverTimeDelta * (*(f32 *)(obj + 0x10) - *(f32 *)(obj + 0x84));
        *(f32 *)(state + 0x498) = *(f32 *)(obj + 0x28);
    }
    if (state[0x3d6] == 0) {
        if ((*(s16 *)(*(int *)(obj + 0x54) + 0x60) & 8) != 0
            && arrayIndexOf(lbl_8032855C, 10, *(s16 *)(other + 0x46)) == -1) {
        } else {
            if (*(void **)(state + 0x42c) == NULL) {
                goto clamp;
            }
            if (*(f32 *)(state + 0x3e0) <= lbl_803E5AEC) {
                goto clamp;
            }
        }
    }
    mag = PSVECMag((f32 *)(obj + 0x24));
    if (mag > lbl_803E5AEC) {
        if (!((HaloSnowBikeFlags *)(state + 0x428))->b02) {
            doRumble(lbl_803E5BC4 * mag);
        }
        *(f32 *)(state + 0x430) = *(f32 *)(state + 0x430) * lbl_803E5BBC;
        if (*(s16 *)(obj + 0x46) == 114 || *(s16 *)(obj + 0x46) == 908) {
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
    if (!((HaloSnowBikeFlags *)(state + 0x428))->b02 && mag > lbl_803E5BC4) {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(mag * lbl_803E5AF8);
    }
    if (*(void **)(state + 0x42c) != NULL) {
        k = lbl_803E5C00;
        OSReport(&lbl_803DC0E4, mag);
        if (*(s16 *)(*(int *)(state + 0x42c) + 0x46) == 909
            || *(s16 *)(*(int *)(state + 0x42c) + 0x46) == 910
            || *(s16 *)(*(int *)(state + 0x42c) + 0x46) == 1236) {
            k = lbl_803E5B88;
        }
        *(f32 *)(obj + 0x24) = k * (oneOverTimeDelta * (*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80)));
        *(f32 *)(obj + 0x2c) = k * (oneOverTimeDelta * (*(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88)));
    } else {
        k2 = lbl_803E5B88;
        *(f32 *)(obj + 0x24) = k2 * (oneOverTimeDelta * (*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80)));
        *(f32 *)(obj + 0x2c) = k2 * (oneOverTimeDelta * (*(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88)));
    }
    Matrix_TransformPoint((f32 *)(state + 0x12c), *(f32 *)(obj + 0x24), lbl_803E5AE8, *(f32 *)(obj + 0x2c),
                          (f32 *)(state + 0x494), &dummy, (f32 *)(state + 0x49c));
clamp:
    v = *(f32 *)(state + 0x494);
    lim = *(f32 *)(state + 0x47c);
    if (v < -lim) {
        c = -lim;
    } else if (v > lim) {
        c = lim;
    } else {
        c = v;
    }
    *(f32 *)(state + 0x494) = c;
    if (*(f32 *)(state + 0x494) < lbl_803E5B8C && *(f32 *)(state + 0x494) > lbl_803E5BA4) {
        *(f32 *)(state + 0x494) = lbl_803E5AE8;
    }
    v = *(f32 *)(state + 0x498);
    lim = *(f32 *)(state + 0x480);
    if (v < -lim) {
        c = -lim;
    } else if (v > lbl_803E5AEC) {
        c = lbl_803E5AEC;
    } else {
        c = v;
    }
    *(f32 *)(state + 0x498) = c;
    if (*(f32 *)(state + 0x498) < lbl_803E5B8C && *(f32 *)(state + 0x498) > lbl_803E5BA4) {
        *(f32 *)(state + 0x498) = lbl_803E5AE8;
    }
    v = *(f32 *)(state + 0x49c);
    lim = *(f32 *)(state + 0x484);
    if (v < -lim) {
        c = -lim;
    } else if (v > lim) {
        c = lim;
    } else {
        c = v;
    }
    *(f32 *)(state + 0x49c) = c;
    if (*(f32 *)(state + 0x49c) < lbl_803E5B8C && *(f32 *)(state + 0x49c) > lbl_803E5BA4) {
        *(f32 *)(state + 0x49c) = lbl_803E5AE8;
    }
    *(f32 *)(state + 0x16c) = *(f32 *)(obj + 0xc);
    *(f32 *)(state + 0x170) = *(f32 *)(obj + 0x10);
    *(f32 *)(state + 0x174) = *(f32 *)(obj + 0x14);
    *(int *)(state + 0x42c) = 0;
}
#pragma peephole reset
#pragma scheduling reset
