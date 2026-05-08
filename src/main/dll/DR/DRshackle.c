#include "ghidra_import.h"
#include "main/dll/DR/DRshackle.h"

extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern f32 fn_801EA678(int p1, int p2);
extern int fn_8005B2FC(double x, double y, double z);
extern int fn_801EC870(int p1, int p2);
extern void fn_800658A4(int p1, f32 x, f32 y, f32 z, f32 *out, int flag);

extern undefined4 *lbl_803DCA6C;
extern undefined4 *lbl_803DCAA8;
extern f32 timeDelta;

extern f32 lbl_803E5AE8; /* 0.0f  */
extern f32 lbl_803E5AEC; /* 1.0f  */
extern f64 lbl_803E5B00; /* int->float magic */
extern f32 lbl_803E5B08; /* 70.0f */
extern f32 lbl_803E5B10; /* 40.0f */
extern f32 lbl_803E5B68; /* 180.0f */
extern f32 lbl_803E5B6C; /* 56.0f */
extern f32 lbl_803E5B70; /* -1.0f */
extern f32 lbl_803E5B74; /* -0.05f */
extern f32 lbl_803E5B78; /* 2.0f */

/* Bitfield: PowerPC big-endian: bit 0 = 0x80, bit 7 = 0x01 */
typedef struct ShackleFlags {
    u8 b7 : 1;  /* 0x80 (sign bit) */
    u8 b6 : 1;  /* 0x40 */
    u8 b5 : 1;  /* 0x20 */
    u8 b4 : 1;  /* 0x10 */
    u8 b3 : 1;  /* 0x08 */
    u8 b2 : 1;  /* 0x04 */
    u8 b1 : 1;  /* 0x02 */
    u8 b0 : 1;  /* 0x01 */
} ShackleFlags;

/*
 * --INFO--
 *
 * Function: fn_801EA854
 * EN v1.0 Address: 0x801EA854
 * EN v1.0 Size: 620b
 */
#pragma peephole off
#pragma scheduling off
int fn_801EA854(int param_1, int param_2)
{
    f32 fVar1;
    f32 fVar2;
    int iVar3;
    int iVar4;
    f32 fade;

    {
        f32 dx = *(f32 *)(param_1 + 0xc);
        f32 dz = *(f32 *)(param_1 + 0x14);
        dx = dx - *(f32 *)(param_2 + 0xc);
        dz = dz - *(f32 *)(param_2 + 0x14);
        fade = lbl_803E5B68 - sqrtf(dx * dx + dz * dz);
    }

    if (*(f32 *)(param_2 + 0x3e4) != lbl_803E5AE8) {
        f32 d = fade - lbl_803E5B10;
        if (d < lbl_803E5AE8) {
            d = lbl_803E5AE8;
        }
        if (d > lbl_803E5B08) {
            d = lbl_803E5B08;
        }
        fade = fade + d;
    }
    if (fade < lbl_803E5AE8) {
        fade = lbl_803E5AE8;
    }

    iVar4 = (*(int (**)(int, int, u8, int, int, f32))(*lbl_803DCA6C + 0x18))(
        param_2, param_2 + 0x28, *(u8 *)(param_2 + 0x5d), 1, 0, fade);

    (*(void (**)(int, int))(*lbl_803DCA6C + 0x14))(param_1, param_2 + 0x28);

    (*(void (**)(int))(*lbl_803DCA6C + 0x2c))(param_2 + 0x28);

    if (iVar4 != 0) {
        *(f32 *)(param_2 + 0x45c) = lbl_803E5AE8;
        return 0;
    }

    iVar3 = (s32)(u16)getAngle(*(f32 *)(param_1 + 0xc) - *(f32 *)(param_2 + 0xc),
                                *(f32 *)(param_1 + 0x14) - *(f32 *)(param_2 + 0x14)) -
             (s32)(u16)*(s16 *)(param_2 + 0x40c);
    if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
    }
    if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
    }
    {
        s32 iVar2 = iVar3 / 0xb6;
        if (iVar2 < -0x41) {
            iVar2 = -0x41;
        } else if (iVar2 > 0x41) {
            iVar2 = 0x41;
        }
        *(f32 *)(param_2 + 0x45c) = (f32)(-iVar2);
    }
    *(s16 *)(param_2 + 0x44c) = 0;
    *(f32 *)(param_2 + 0x45c) = *(f32 *)(param_2 + 0x45c) / lbl_803E5B6C;

    {
        f32 fVar1 = *(f32 *)(param_2 + 0x45c);
        f32 fVar2 = lbl_803E5B70;
        if (fVar1 < lbl_803E5B70) {
        } else if (fVar1 > lbl_803E5AEC) {
            fVar2 = lbl_803E5AEC;
        } else {
            fVar2 = fVar1;
        }
        *(f32 *)(param_2 + 0x45c) = fVar2;
    }

    {
        f32 ang = fn_801EA678(param_1, param_2);
        ang = -ang;
        if (*(f32 *)(param_2 + 0x49c) < ang || iVar3 > 0x2aaa || iVar3 < -0x2aaa) {
            *(int *)(param_2 + 0x458) = 0;
        } else if (*(f32 *)(param_2 + 0x49c) > ang) {
            *(int *)(param_2 + 0x458) = 0x100;
        }
    }
    return 1;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_801EAAC0
 * EN v1.0 Address: 0x801EAAC0
 * EN v1.0 Size: 908b
 */
#pragma peephole off
#pragma scheduling off
int fn_801EAAC0(int param_1, int param_2)
{
    ShackleFlags *flags;
    int iVar3;
    int iVar4;
    s16 angle;
    f32 local_8;

    flags = (ShackleFlags *)(param_2 + 0x428);
    if (flags->b3 == 0) {
        return 0;
    }
    iVar3 = fn_8005B2FC(*(f32 *)(param_1 + 0xc), *(f32 *)(param_1 + 0x10), *(f32 *)(param_1 + 0x14));
    if (iVar3 > -1) {
        if (flags->b0 == 0) {
        {
            f32 zero = lbl_803E5AE8;
            *(f32 *)(param_2 + 0x494) = zero;
            *(f32 *)(param_2 + 0x498) = zero;
        }
        *(f32 *)(param_2 + 0x49c) = -fn_801EA678(param_1, param_2);
        iVar4 = (*(int (**)(int, int, f32, u8, int, int))(*lbl_803DCA6C + 0x18))(
            param_2, param_2 + 0x28,
            -*(f32 *)(param_2 + 0x49c) * timeDelta,
            *(u8 *)(param_2 + 0x5d), 1, 0);
        (*(void (**)(int, int))(*lbl_803DCA6C + 0x14))(param_1, param_2 + 0x28);
        (*(void (**)(int))(*lbl_803DCA6C + 0x2c))(param_2 + 0x28);
        if (iVar4 != 0) {
            return 0;
        }

        fn_801EC870(param_1, param_2);
        angle = (s16)getAngle(*(f32 *)(param_1 + 0xc) - *(f32 *)(param_2 + 0xc),
                              *(f32 *)(param_1 + 0x14) - *(f32 *)(param_2 + 0x14));
        *(s16 *)(param_1) = angle;
        *(s16 *)(param_2 + 0x40e) = angle;
        *(s16 *)(param_2 + 0x40c) = angle;
        *(f32 *)(param_2 + 0x430) = lbl_803E5B74;
        *(f32 *)(param_1 + 0xc) = *(f32 *)(param_2 + 0xc);
        *(f32 *)(param_1 + 0x10) = *(f32 *)(param_2 + 0x10);
        *(f32 *)(param_1 + 0x14) = *(f32 *)(param_2 + 0x14);
        (*(void (**)(int, int))(*lbl_803DCAA8 + 0x20))(param_1, param_2 + 0x178);
        *(f32 *)(*(int *)(param_1 + 0x54) + 0x10) = *(f32 *)(param_1 + 0xc);
        *(f32 *)(*(int *)(param_1 + 0x54) + 0x14) = *(f32 *)(param_1 + 0x10);
        *(f32 *)(*(int *)(param_1 + 0x54) + 0x18) = *(f32 *)(param_1 + 0x14);
        *(f32 *)(*(int *)(param_1 + 0x54) + 0x1c) = *(f32 *)(param_1 + 0x18);
        *(f32 *)(*(int *)(param_1 + 0x54) + 0x20) = *(f32 *)(param_1 + 0x1c);
        *(f32 *)(*(int *)(param_1 + 0x54) + 0x24) = *(f32 *)(param_1 + 0x20);

        if (*(u8 *)(param_2 + 0x434) == 0) {
            fn_800658A4(param_1, *(f32 *)(param_1 + 0xc),
                        *(f32 *)(param_1 + 0x10), *(f32 *)(param_1 + 0x14),
                        &local_8, 0);
            *(f32 *)(param_1 + 0x10) = *(f32 *)(param_1 + 0x10) - local_8;
            *(f32 *)(param_1 + 0x10) = *(f32 *)(param_1 + 0x10) + lbl_803E5B78;
        }
        flags->b0 = 1;
        return 0;
        }
        return fn_801EA854(param_1, param_2) != 0;
    }

    /* iVar3 <= -1 path */
    iVar4 = (*(int (**)(int, int, f32, u8, int, int))(*lbl_803DCA6C + 0x18))(
        param_2, param_2 + 0x28, timeDelta * fn_801EA678(param_1, param_2),
        *(u8 *)(param_2 + 0x5d), 1, 0);
    (*(void (**)(int, int))(*lbl_803DCA6C + 0x14))(param_1, param_2 + 0x28);
    (*(void (**)(int))(*lbl_803DCA6C + 0x2c))(param_2 + 0x28);
    if (iVar4 != 0) {
        return 0;
    }

    angle = (s16)getAngle(*(f32 *)(param_1 + 0xc) - *(f32 *)(param_2 + 0xc),
                          *(f32 *)(param_1 + 0x14) - *(f32 *)(param_2 + 0x14));
    *(s16 *)(param_1) = angle;
    *(f32 *)(param_1 + 0xc) = *(f32 *)(param_2 + 0xc);
    *(f32 *)(param_1 + 0x10) = *(f32 *)(param_2 + 0x10);
    *(f32 *)(param_1 + 0x14) = *(f32 *)(param_2 + 0x14);
    (*(void (**)(int, int))(*lbl_803DCAA8 + 0x20))(param_1, param_2 + 0x178);
    *(f32 *)(*(int *)(param_1 + 0x54) + 0x10) = *(f32 *)(param_1 + 0xc);
    *(f32 *)(*(int *)(param_1 + 0x54) + 0x14) = *(f32 *)(param_1 + 0x10);
    *(f32 *)(*(int *)(param_1 + 0x54) + 0x18) = *(f32 *)(param_1 + 0x14);
    *(f32 *)(*(int *)(param_1 + 0x54) + 0x1c) = *(f32 *)(param_1 + 0x18);
    *(f32 *)(*(int *)(param_1 + 0x54) + 0x20) = *(f32 *)(param_1 + 0x1c);
    *(f32 *)(*(int *)(param_1 + 0x54) + 0x24) = *(f32 *)(param_1 + 0x20);
    flags->b0 = 0;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset
