#include "main/dll/DR/DRpickup.h"

#pragma peephole off
#pragma scheduling off

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Matrix_TransformPoint(void *mtx, float x, float y, float z, float *ox, float *oy, float *oz);
extern void PSVECAdd(const void *a, const void *b, void *ab);
extern float powfBitEstimate(float x, float y);

extern void **gCameraInterface;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B8C;
extern f32 lbl_803E5BA4;
extern f32 lbl_803E5C28;
extern f32 lbl_803E5C2C;
extern f32 lbl_803E5C30;

/*
 * --INFO--
 *
 * Function: fn_801EC1AC
 * EN v1.0 Address: 0x801EC1AC
 * EN v1.0 Size: 1524b
 */
void fn_801EC1AC(int param_1, int param_2)
{
    PickupFlags *flags;
    int origBit4;
    f32 fVar3;
    f32 fVar2;
    f32 fVar4;
    f32 fLim;
    f32 out[3];
    f32 vec_args[4];

    flags = (PickupFlags *)(param_2 + 0x428);
    origBit4 = flags->b4;

    if ((*(u32 *)(param_2 + 0x458) & 0x100) != 0) {
        flags->b6 = 1;
    } else {
        flags->b6 = 0;
    }

    if ((*(u32 *)(param_2 + 0x458) & 0x200) != 0) {
        flags->b4 = 1;
    } else {
        flags->b4 = 0;
    }

    if ((origBit4 == 0) && (flags->b4 != 0)) {
        Sfx_PlayFromObject(param_1, 0x45f);
    }

    /* Damping #1: update 0x430 (rotation/angle) */
    fVar2 = lbl_803E5AE8;
    if (flags->b6 != 0) {
        fVar2 = *(f32 *)(param_2 + 0x538);
    }
    fVar3 = (fVar2 - *(f32 *)(param_2 + 0x430)) * lbl_803E5C28;
    fVar4 = (fVar3 < lbl_803E5C2C) ? lbl_803E5C2C
                                   : ((fVar3 > lbl_803E5B8C) ? lbl_803E5B8C : fVar3);
    *(f32 *)(param_2 + 0x430) = fVar4 * timeDelta + *(f32 *)((int)param_2 + 0x430);

    /* Velocity calc on 0x4a8 */
    fVar2 = lbl_803E5AE8;
    if (flags->b4 != 0) {
        f32 vy53c = *(f32 *)(param_2 + 0x53c);
        f32 v49c = *(f32 *)(param_2 + 0x49c);
        if (v49c <= fVar2) {
            f32 nv = -vy53c;
            f32 lim = -v49c * oneOverTimeDelta;
            if (!(nv < lim)) {
                lim = (nv > fVar2) ? fVar2 : nv;
            }
            fVar2 = lim;
        } else {
            if (!(vy53c < fVar2)) {
                fVar2 = -v49c * oneOverTimeDelta;
                if (!(vy53c > fVar2)) {
                    fVar2 = vy53c;
                }
            }
        }
    }
    *(f32 *)(param_2 + 0x4a0) = lbl_803E5AE8;
    *(f32 *)(param_2 + 0x4a4) = lbl_803E5AE8;
    *(f32 *)(param_2 + 0x4a8) = (*(f32 *)(param_2 + 0x430) + fVar2) * timeDelta;

    /* Two TransformPoint calls reusing the same out_x/out_y/out_z buffer */
    Matrix_TransformPoint((void *)(param_2 + 0x6c),
                          *(f32 *)(param_2 + 0x4a0),
                          *(f32 *)(param_2 + 0x4a4),
                          *(f32 *)(param_2 + 0x4a8),
                          &out[0], &out[1], &out[2]);
    Matrix_TransformPoint((void *)(param_2 + 0x12c),
                          out[0], out[1], out[2],
                          &out[0], &out[1], &out[2]);
    PSVECAdd(out, (void *)(param_2 + 0x494), (void *)(param_2 + 0x494));

    /* 0x414 update with negated 0x45c * 0x52c then powfBitEstimate */
    *(f32 *)(param_2 + 0x414) =
        (-*(f32 *)(param_2 + 0x45c) * *(f32 *)(param_2 + 0x52c)) * timeDelta +
        *(f32 *)(param_2 + 0x414);
    *(f32 *)(param_2 + 0x414) =
        powfBitEstimate(*(f32 *)(param_2 + 0x530), timeDelta) *
        *(f32 *)(param_2 + 0x414);

    /* Clamp 0x414 to [-0x534, 0x534] */
    fVar2 = *(f32 *)(param_2 + 0x414);
    fVar3 = *(f32 *)(param_2 + 0x534);
    fLim = -fVar3;
    *(f32 *)(param_2 + 0x414) = (fVar2 < fLim) ? fLim
                                               : ((fVar2 > fVar3) ? fVar3 : fVar2);

    /* Apply 0x414 * timeDelta to short at 0x40e, then chase the scaled
       angular velocity through 0x410 with overflow normalization. */
    {
        f32 newF = (f32)(s32)*(s16 *)(param_2 + 0x40e) +
                   *(f32 *)(param_2 + 0x414) * timeDelta;
        s32 delta;
        *(s16 *)(param_2 + 0x40e) = newF;
        delta = (s32)(*(f32 *)(param_2 + 0x414) * *(f32 *)(param_2 + 0x550)) -
                (s32)(u16)*(u32 *)(param_2 + 0x410);
        if (delta > 0x8000) {
            delta = delta - 0xFFFF;
        }
        if (delta < -0x8000) {
            delta = delta + 0xFFFF;
        }
        *(u32 *)(param_2 + 0x410) =
            (u32)(s32)((f32)delta * *(f32 *)(param_2 + 0x554) +
                       (f32)(s32)*(u32 *)((int)param_2 + 0x410));
    }
    {
        s32 delta = (s32)*(s16 *)(param_2 + 0x40e) - (s32)(u16)*(s16 *)(param_2 + 0x40c);
        if (delta > 0x8000) {
            delta = delta - 0xFFFF;
        }
        if (delta < -0x8000) {
            delta = delta + 0xFFFF;
        }
        *(s16 *)(param_2 + 0x40c) = (s16)((f32)delta * *(f32 *)(param_2 + 0x558) +
                                          (f32)(s32)*(s16 *)(param_2 + 0x40c));
    }

    /* Bit 7 (>>7 & 1) check on 0x428 = mask 0x80 = flags->b7 (first bitfield = MSB) */
    if (flags->b7 != 0) {
        *(f32 *)(param_2 + 0x584) =
            (-*(f32 *)(param_2 + 0x570)) * timeDelta + *(f32 *)(param_2 + 0x584);
        {
            f32 v = *(f32 *)(param_2 + 0x584);
            *(f32 *)(param_2 + 0x584) = (v < lbl_803E5C30) ? lbl_803E5C30
                                        : ((v > lbl_803E5B48) ? lbl_803E5B48 : v);
        }
        *(s16 *)(param_1 + 0x2) = (f32)(s32)*(s16 *)(param_1 + 0x2) +
                                  *(f32 *)(param_2 + 0x584) * timeDelta;
    }

    /* Bit 1 (>>1 & 1) check on 0x428 = mask 0x02 = flags->b1 (7th bitfield) */
    if (flags->b1 == 0) {
        vec_args[0] = *(f32 *)(param_2 + 0x414);
        vec_args[1] = *(f32 *)(param_2 + 0x49c);
        vec_args[2] = (f32)(s32)*(s16 *)(param_1 + 0x4);
        vec_args[3] = (f32)(s32)*(s16 *)(param_1 + 0x2);
        (*(void (**)(void *, int, void *))((u8 *)*gCameraInterface + 0x60))(
            vec_args, 0x10, *gCameraInterface);
    }

    /* Clamp 0x494 to [-0x47c, 0x47c] */
    {
        f32 lim = *(f32 *)(param_2 + 0x47c);
        f32 v = *(f32 *)(param_2 + 0x494);
        f32 result = -lim;
        *(f32 *)(param_2 + 0x494) = (v < result) ? result : ((v > lim) ? lim : v);
        v = *(f32 *)(param_2 + 0x494);
        if (v < lbl_803E5B8C) {
            if (v > lbl_803E5BA4) {
                *(f32 *)(param_2 + 0x494) = lbl_803E5AE8;
            }
        }
    }

    /* Clamp 0x498 to [-0x480, lbl_803E5AEC] */
    {
        f32 v = *(f32 *)(param_2 + 0x498);
        f32 lim = -*(f32 *)(param_2 + 0x480);
        *(f32 *)(param_2 + 0x498) = (v < lim) ? lim
                                    : ((v > lbl_803E5AEC) ? lbl_803E5AEC : v);
        v = *(f32 *)(param_2 + 0x498);
        if (v < lbl_803E5B8C) {
            if (v > lbl_803E5BA4) {
                *(f32 *)(param_2 + 0x498) = lbl_803E5AE8;
            }
        }
    }

    /* Clamp 0x49c to [-0x484, 0x484] */
    {
        f32 lim = *(f32 *)(param_2 + 0x484);
        f32 v = *(f32 *)(param_2 + 0x49c);
        f32 result = -lim;
        *(f32 *)(param_2 + 0x49c) = (v < result) ? result : ((v > lim) ? lim : v);
        v = *(f32 *)(param_2 + 0x49c);
        if (v < lbl_803E5B8C) {
            if (v > lbl_803E5BA4) {
                *(f32 *)(param_2 + 0x49c) = lbl_803E5AE8;
            }
        }
    }
}
