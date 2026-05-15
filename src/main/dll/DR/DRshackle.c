#include "ghidra_import.h"
#include "main/dll/DR/DRshackle.h"

extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern f32 fn_801EA678(int p1, int p2);
extern int objPosToMapBlockIdx(double x, double y, double z);
extern int fn_801EC870(int p1, int p2);
extern void hitDetectFn_800658a4(int p1, f32 x, f32 y, f32 z, f32 *out, int flag);

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

#define DRSHACKLE_COLLIDER_OFFSET 0x28
#define DRSHACKLE_COLLIDER_MODE_OFFSET 0x5d
#define DRSHACKLE_MODEL_OFFSET 0x54

#define DRSHACKLE_FLAGS_OFFSET 0x428
#define DRSHACKLE_SWING_ACCEL_OFFSET 0x430
#define DRSHACKLE_FLOOR_ADJUST_FLAG_OFFSET 0x434
#define DRSHACKLE_YAW_OFFSET 0x40c
#define DRSHACKLE_TARGET_YAW_OFFSET 0x40e
#define DRSHACKLE_SWING_COMMAND_OFFSET 0x44c
#define DRSHACKLE_SWING_RETURN_OFFSET 0x458
#define DRSHACKLE_SWING_BLEND_OFFSET 0x45c
#define DRSHACKLE_DISTANCE_FADE_OFFSET 0x3e4
#define DRSHACKLE_LAST_PITCH_OFFSET 0x49c
#define DRSHACKLE_ATTACHMENT_OFFSET 0x178

#define DRSHACKLE_ANGLE_STEP 0xb6
#define DRSHACKLE_SWING_BLEND_LIMIT 0x41
#define DRSHACKLE_SWING_RETURN_LEFT 0x100
#define DRSHACKLE_ANGLE_RETURN_LIMIT 0x2aaa

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
int fn_801EA854(int obj, int state)
{
    f32 fVar1;
    f32 fVar2;
    int iVar3;
    int iVar4;
    f32 fade;

    {
        f32 dx = *(f32 *)(obj + 0xc);
        f32 dz = *(f32 *)(obj + 0x14);
        dx = dx - *(f32 *)(state + 0xc);
        dz = dz - *(f32 *)(state + 0x14);
        fade = lbl_803E5B68 - sqrtf(dx * dx + dz * dz);
    }

    if (*(f32 *)(state + DRSHACKLE_DISTANCE_FADE_OFFSET) != lbl_803E5AE8) {
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
        state, state + DRSHACKLE_COLLIDER_OFFSET, *(u8 *)(state + DRSHACKLE_COLLIDER_MODE_OFFSET),
        1, 0, fade);

    (*(void (**)(int, int))(*lbl_803DCA6C + 0x14))(obj, state + DRSHACKLE_COLLIDER_OFFSET);

    (*(void (**)(int))(*lbl_803DCA6C + 0x2c))(state + DRSHACKLE_COLLIDER_OFFSET);

    if (iVar4 != 0) {
        *(f32 *)(state + DRSHACKLE_SWING_BLEND_OFFSET) = lbl_803E5AE8;
        return 0;
    }

    iVar3 = (s32)(u16)getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(state + 0xc),
                                *(f32 *)(obj + 0x14) - *(f32 *)(state + 0x14)) -
             (s32)(u16)*(s16 *)(state + DRSHACKLE_YAW_OFFSET);
    if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
    }
    if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
    }
    {
        s32 iVar2 = iVar3 / DRSHACKLE_ANGLE_STEP;
        if (iVar2 < -DRSHACKLE_SWING_BLEND_LIMIT) {
            iVar2 = -DRSHACKLE_SWING_BLEND_LIMIT;
        } else if (iVar2 > DRSHACKLE_SWING_BLEND_LIMIT) {
            iVar2 = DRSHACKLE_SWING_BLEND_LIMIT;
        }
        *(f32 *)(state + DRSHACKLE_SWING_BLEND_OFFSET) = (f32)(-iVar2);
    }
    *(s16 *)(state + DRSHACKLE_SWING_COMMAND_OFFSET) = 0;
    *(f32 *)(state + DRSHACKLE_SWING_BLEND_OFFSET) =
        *(f32 *)(state + DRSHACKLE_SWING_BLEND_OFFSET) / lbl_803E5B6C;

    {
        f32 fVar1 = *(f32 *)(state + DRSHACKLE_SWING_BLEND_OFFSET);
        f32 fVar2 = lbl_803E5B70;
        if (fVar1 < lbl_803E5B70) {
        } else if (fVar1 > lbl_803E5AEC) {
            fVar2 = lbl_803E5AEC;
        } else {
            fVar2 = fVar1;
        }
        *(f32 *)(state + DRSHACKLE_SWING_BLEND_OFFSET) = fVar2;
    }

    {
        f32 ang = fn_801EA678(obj, state);
        ang = -ang;
        if (*(f32 *)(state + DRSHACKLE_LAST_PITCH_OFFSET) < ang ||
            iVar3 > DRSHACKLE_ANGLE_RETURN_LIMIT || iVar3 < -DRSHACKLE_ANGLE_RETURN_LIMIT) {
            *(int *)(state + DRSHACKLE_SWING_RETURN_OFFSET) = 0;
        } else if (*(f32 *)(state + DRSHACKLE_LAST_PITCH_OFFSET) > ang) {
            *(int *)(state + DRSHACKLE_SWING_RETURN_OFFSET) = DRSHACKLE_SWING_RETURN_LEFT;
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
int fn_801EAAC0(int obj, int state)
{
    ShackleFlags *flags;
    int iVar3;
    int iVar4;
    s16 angle;
    f32 local_8;

    flags = (ShackleFlags *)(state + DRSHACKLE_FLAGS_OFFSET);
    if (flags->b3 == 0) {
        return 0;
    }
    iVar3 = objPosToMapBlockIdx(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
    if (iVar3 > -1) {
        if (flags->b0 == 0) {
        {
            f32 zero = lbl_803E5AE8;
            *(f32 *)(state + 0x494) = zero;
            *(f32 *)(state + 0x498) = zero;
        }
        *(f32 *)(state + DRSHACKLE_LAST_PITCH_OFFSET) = -fn_801EA678(obj, state);
        iVar4 = (*(int (**)(int, int, f32, u8, int, int))(*lbl_803DCA6C + 0x18))(
            state, state + DRSHACKLE_COLLIDER_OFFSET,
            -*(f32 *)(state + DRSHACKLE_LAST_PITCH_OFFSET) * timeDelta,
            *(u8 *)(state + DRSHACKLE_COLLIDER_MODE_OFFSET), 1, 0);
        (*(void (**)(int, int))(*lbl_803DCA6C + 0x14))(obj, state + DRSHACKLE_COLLIDER_OFFSET);
        (*(void (**)(int))(*lbl_803DCA6C + 0x2c))(state + DRSHACKLE_COLLIDER_OFFSET);
        if (iVar4 != 0) {
            return 0;
        }

        fn_801EC870(obj, state);
        angle = (s16)getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(state + 0xc),
                              *(f32 *)(obj + 0x14) - *(f32 *)(state + 0x14));
        *(s16 *)(obj) = angle;
        *(s16 *)(state + DRSHACKLE_TARGET_YAW_OFFSET) = angle;
        *(s16 *)(state + DRSHACKLE_YAW_OFFSET) = angle;
        *(f32 *)(state + DRSHACKLE_SWING_ACCEL_OFFSET) = lbl_803E5B74;
        *(f32 *)(obj + 0xc) = *(f32 *)(state + 0xc);
        *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x10);
        *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x14);
        (*(void (**)(int, int))(*lbl_803DCAA8 + 0x20))(obj, state + DRSHACKLE_ATTACHMENT_OFFSET);
        *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x10) = *(f32 *)(obj + 0xc);
        *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x14) = *(f32 *)(obj + 0x10);
        *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x18) = *(f32 *)(obj + 0x14);
        *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x1c) = *(f32 *)(obj + 0x18);
        *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x20) = *(f32 *)(obj + 0x1c);
        *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x24) = *(f32 *)(obj + 0x20);

        if (*(u8 *)(state + DRSHACKLE_FLOOR_ADJUST_FLAG_OFFSET) == 0) {
            hitDetectFn_800658a4(obj, *(f32 *)(obj + 0xc),
                        *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14),
                        &local_8, 0);
            *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) - local_8;
            *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) + lbl_803E5B78;
        }
        flags->b0 = 1;
        return 0;
        }
        return fn_801EA854(obj, state) != 0;
    }

    /* iVar3 <= -1 path */
    iVar4 = (*(int (**)(int, int, f32, u8, int, int))(*lbl_803DCA6C + 0x18))(
        state, state + DRSHACKLE_COLLIDER_OFFSET, timeDelta * fn_801EA678(obj, state),
        *(u8 *)(state + DRSHACKLE_COLLIDER_MODE_OFFSET), 1, 0);
    (*(void (**)(int, int))(*lbl_803DCA6C + 0x14))(obj, state + DRSHACKLE_COLLIDER_OFFSET);
    (*(void (**)(int))(*lbl_803DCA6C + 0x2c))(state + DRSHACKLE_COLLIDER_OFFSET);
    if (iVar4 != 0) {
        return 0;
    }

    angle = (s16)getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(state + 0xc),
                          *(f32 *)(obj + 0x14) - *(f32 *)(state + 0x14));
    *(s16 *)(obj) = angle;
    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0xc);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x10);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x14);
    (*(void (**)(int, int))(*lbl_803DCAA8 + 0x20))(obj, state + DRSHACKLE_ATTACHMENT_OFFSET);
    *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x10) = *(f32 *)(obj + 0xc);
    *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x14) = *(f32 *)(obj + 0x10);
    *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x18) = *(f32 *)(obj + 0x14);
    *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x1c) = *(f32 *)(obj + 0x18);
    *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x20) = *(f32 *)(obj + 0x1c);
    *(f32 *)(*(int *)(obj + DRSHACKLE_MODEL_OFFSET) + 0x24) = *(f32 *)(obj + 0x20);
    flags->b0 = 0;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset
