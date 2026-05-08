#include "ghidra_import.h"
#include "main/dll/DR/DRpickup.h"

#pragma peephole off
#pragma scheduling off

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Matrix_TransformPoint(void *mtx, float x, float y, float z, float *ox, float *oy, float *oz);
extern void PSVECAdd(const void *a, const void *b, void *ab);
extern float powfBitEstimate(float x, float y);

extern void **lbl_803DCA50;
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

/* Bitfield: PowerPC big-endian: bit 0 = 0x80, bit 7 = 0x01 */
typedef struct PickupFlags {
    u8 b7 : 1;  /* 0x80 (sign bit) */
    u8 b6 : 1;  /* 0x40 */
    u8 b5 : 1;  /* 0x20 */
    u8 b4 : 1;  /* 0x10 */
    u8 b3 : 1;  /* 0x08 */
    u8 b2 : 1;  /* 0x04 */
    u8 b1 : 1;  /* 0x02 */
    u8 b0 : 1;  /* 0x01 */
} PickupFlags;

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
    f32 vec_args[4];
    f32 out_x, out_y, out_z;

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
    fVar4 = lbl_803E5C2C;
    if (!(fVar3 < fVar4)) {
        fVar4 = lbl_803E5B8C;
        if (!(fVar3 > fVar4)) {
            fVar4 = fVar3;
        }
    }
    *(f32 *)(param_2 + 0x430) = fVar4 * timeDelta + *(f32 *)(param_2 + 0x430);

    /* Velocity calc on 0x4a8 */
    fVar2 = lbl_803E5AE8;
    if (flags->b4 != 0) {
        f32 vy53c = *(f32 *)(param_2 + 0x53c);
        f32 v49c = *(f32 *)(param_2 + 0x49c);
        if (v49c <= fVar2) {
            f32 nv = -vy53c;
            f32 lim = -v49c * oneOverTimeDelta;
            if (!(nv < lim)) {
                if (nv > fVar2) {
                    fVar2 = fVar2;
                } else {
                    fVar2 = nv;
                }
            } else {
                fVar2 = lim;
            }
        } else {
            if (!(vy53c < fVar2)) {
                f32 lim = -v49c * oneOverTimeDelta;
                if (!(vy53c > lim)) {
                    fVar2 = vy53c;
                } else {
                    fVar2 = lim;
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
                          &out_x, &out_y, &out_z);
    Matrix_TransformPoint((void *)(param_2 + 0x12c),
                          out_x, out_y, out_z,
                          &out_x, &out_y, &out_z);
    PSVECAdd(&out_x, (void *)(param_2 + 0x494), (void *)(param_2 + 0x494));

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
    if (!(fVar2 < fLim)) {
        if (fVar2 > fVar3) {
            fLim = fVar3;
        } else {
            fLim = fVar2;
        }
    }
    *(f32 *)(param_2 + 0x414) = fLim;

    /* Apply 0x414 * timeDelta to short at 0x40e (with overflow normalization) */
    {
        f32 newF = (f32)(s32)*(s16 *)(param_2 + 0x40e) +
                   *(f32 *)(param_2 + 0x414) * timeDelta;
        s32 newI = (s32)newF;
        s32 delta;
        *(s16 *)(param_2 + 0x40e) = (s16)newI;
        delta = newI - (s32)(u16)*(u32 *)(param_2 + 0x410);
        if (delta > 0x8000) {
            delta = delta - 0xFFFF;
        }
        if (delta < -0x8000) {
            delta = delta + 0xFFFF;
        }
        *(u32 *)(param_2 + 0x410) =
            (u32)(s32)((f32)delta * *(f32 *)(param_2 + 0x554) +
                       (f32)(s32)*(u32 *)(param_2 + 0x410));
    }
    {
        s32 delta = (s32)*(s16 *)(param_2 + 0x40e) - (s32)(u16)*(u32 *)(param_2 + 0x40c);
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
            f32 result = lbl_803E5C30;
            if (!(v < result)) {
                result = lbl_803E5B48;
                if (!(v > result)) {
                    result = v;
                }
            }
            *(f32 *)(param_2 + 0x584) = result;
        }
        {
            s32 newI = (s32)((f32)(s32)*(s16 *)(param_1 + 0x2) +
                             *(f32 *)(param_2 + 0x584) * timeDelta);
            *(s16 *)(param_1 + 0x2) = (s16)newI;
        }
    }

    /* Bit 1 (>>1 & 1) check on 0x428 = mask 0x02 = flags->b1 (7th bitfield) */
    if (flags->b1 == 0) {
        vec_args[0] = *(f32 *)(param_2 + 0x414);
        vec_args[1] = *(f32 *)(param_2 + 0x49c);
        vec_args[2] = (f32)(s32)*(s16 *)(param_1 + 0x4);
        vec_args[3] = (f32)(s32)*(s16 *)(param_1 + 0x2);
        (*(void (**)(void *, int, void *))(((void **)*lbl_803DCA50)[0x60 / 4]))(
            vec_args, 0x10, *lbl_803DCA50);
    }

    /* Clamp 0x494 to [-0x47c, 0x47c] */
    {
        f32 lim = *(f32 *)(param_2 + 0x47c);
        f32 v = *(f32 *)(param_2 + 0x494);
        f32 result = -lim;
        if (!(v < -lim)) {
            if (v > lim) {
                result = lim;
            } else {
                result = v;
            }
        }
        *(f32 *)(param_2 + 0x494) = result;
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
        f32 result = lim;
        if (!(v < lim)) {
            result = lbl_803E5AEC;
            if (!(v > result)) {
                result = v;
            }
        }
        *(f32 *)(param_2 + 0x498) = result;
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
        if (!(v < -lim)) {
            if (v > lim) {
                result = lim;
            } else {
                result = v;
            }
        }
        *(f32 *)(param_2 + 0x49c) = result;
        v = *(f32 *)(param_2 + 0x49c);
        if (v < lbl_803E5B8C) {
            if (v > lbl_803E5BA4) {
                *(f32 *)(param_2 + 0x49c) = lbl_803E5AE8;
            }
        }
    }
}
