#include "ghidra_import.h"
#include "main/dll/DR/DRshackle.h"

extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern f32 fn_801EA678(int p1, int p2);

extern undefined4 *lbl_803DCA6C;

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
int fn_801EAAC0(int param_1, int param_2)
{
    /* Stub: not yet decomped */
    (void)param_1;
    (void)param_2;
    return 0;
}
