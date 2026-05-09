#include "ghidra_import.h"

extern void GameBit_Set(int eventId, int value);
extern void ObjGroup_RemoveObject(int obj, int group);

extern undefined4 *lbl_803DCA8C;
extern undefined4 *lbl_803DCAA8;
extern f32 lbl_803E8234;
extern f32 lbl_803E8258;
extern f32 lbl_803E827C;
extern f32 lbl_803E8298;
extern f32 lbl_803E829C;

extern void setMatrixFromObjectPos(void *matrix, void *packedTransform);
extern void Matrix_TransformPoint(double x, double y, double z, void *matrix, undefined4 outX,
                                  undefined4 outY, undefined4 outZ);

/*
 * Empty stub.
 */
void fn_802BB718(void) {}

/*
 * Returns 0.
 */
int fn_802BB71C(void) { return 0; }

/*
 * Returns floored neg-velocity-Y in *out, or a constant if mode != 10;
 * also returns f1 = constant.
 */
void fn_802BB724(int obj, f32 *out)
{
    int state = *(int *)(obj + 0xb8);
    if (*(s16 *)(state + 0x274) == 0xa) {
        *out = -*(f32 *)(state + 0x2a0);
    } else {
        *out = lbl_803E827C;
    }
    /* f1 return clobbered by caller via convention (f1 = lbl_803E8234) */
    (void)lbl_803E8234;
}

/*
 * Sets *out_f = 0.0f, *out_i = 0.
 */
void fn_802BB754(void *unused, f32 *out_f, int *out_i)
{
    (void)unused;
    *out_f = lbl_803E8234;
    *out_i = 0;
}

/*
 * Stores arg at obj->state[0xa8a] (low byte).
 */
void fn_802BB008(int obj, u8 value)
{
    *(u8 *)(*(int *)(obj + 0xb8) + 0xa8a) = value;
}

/*
 * Returns 0.
 */
int fn_802BB018(void) { return 0; }

/*
 * Build a transform from a packed rotation/translation record and sample
 * one fixed local point through it.
 */
#pragma dont_inline on
void fn_802BB020(undefined2 *packed, undefined4 outX, undefined4 outY, undefined4 outZ)
{
    undefined2 local_68;
    undefined2 local_66;
    undefined2 local_64;
    f32 local_60;
    undefined4 local_5c;
    undefined4 local_58;
    undefined4 local_54;
    undefined matrix[68];

    local_5c = *(undefined4 *)(packed + 6);
    local_58 = *(undefined4 *)(packed + 8);
    local_54 = *(undefined4 *)(packed + 10);
    local_68 = packed[0];
    local_66 = packed[1];
    local_64 = packed[2];
    local_60 = lbl_803E8258;
    setMatrixFromObjectPos(matrix, &local_68);
    Matrix_TransformPoint(lbl_803E8234, lbl_803E8298, lbl_803E829C, matrix, outX, outY, outZ);
}
#pragma dont_inline reset

/*
 * Returns 2 if state->[0xa8f] != 0, else 1.
 */
int fn_802BB0C4(int obj)
{
    if (*(u8 *)(*(int *)(obj + 0xb8) + 0xa8f) != 0) {
        return 2;
    }
    return 1;
}

/*
 * If bit 1 of state->[0xa8e] is set, set GameBit 0x3e3 to 0, clear
 * the bit, and return 1. Otherwise return 0.
 */
int fn_802BB0E4(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if ((*(u8 *)(state + 0xa8e) & 0x2) != 0) {
        GameBit_Set(0x3e3, 0);
        *(u8 *)(state + 0xa8e) = (u8)(*(u8 *)(state + 0xa8e) & ~0x2);
        return 1;
    }
    return 0;
}

/*
 * Read 3 floats from state into the 3 output pointers.
 */
void fn_802BB144(int obj, f32 *out_x, f32 *out_y, f32 *out_z)
{
    int state = *(int *)(obj + 0xb8);
    *out_x = *(f32 *)(state + 0x9e8);
    *out_y = *(f32 *)(state + 0x9ec);
    *out_z = *(f32 *)(state + 0x9f0);
}

/*
 * Returns 1 if state->[0xa90] != 0, else 2.
 */
int gdev_cc_initinterrupts(int obj)
{
    if (*(u8 *)(*(int *)(obj + 0xb8) + 0xa90) != 0) {
        return 1;
    }
    return 2;
}

/*
 * ddh_cc_initinterrupts - large interrupt-init helper (~140 instructions).
 */
#pragma dont_inline on
int ddh_cc_initinterrupts(int obj, undefined4 unused, int setup)
{
    u8 mode;
    int state;
    int animState;
    int i;

    (void)unused;
    state = *(int *)(obj + 0xb8);
    *(u8 *)(obj + 0xaf) |= 8;
    mode = *(u8 *)(state + 0xa8c);

    if (mode == 3) {
        *(u8 *)(setup + 0x56) = 0;
        *(u8 *)(state + 0x27a) = 1;
        (*(void (*)(int, int, int))(*lbl_803DCA8C + 0x14))(obj, state, 7);
    } else if (mode < 3) {
        if (mode == 1) {
            *(u8 *)(setup + 0x56) = 0;
            if (*(s16 *)(obj + 0xb4) == -1) {
                animState = 7;
            } else if ((*(u8 *)(state + 0xa8d) == 4) || (3 < *(u8 *)(state + 0xa8d))) {
                animState = 7;
            } else {
                animState = 6;
            }
            (*(void (*)(int, int, int))(*lbl_803DCA8C + 0x14))(obj, state, animState);
        } else if (mode == 0) {
            *(u8 *)(setup + 0x56) = 0;
            if (*(s16 *)(obj + 0xb4) == -1) {
                for (i = 0; i < (int)(u32)*(u8 *)(setup + 0x8b); i++) {
                    GameBit_Set(0x17b, 1);
                    *(u8 *)(state + 0xa8e) |= 0x20;
                }
            }
            (*(void (*)(int, int, int))(*lbl_803DCA8C + 0x14))(obj, state, 1);
        }
    } else if (mode == 5) {
        *(u8 *)(setup + 0x56) = 0;
        (*(void (*)(int, int, int))(*lbl_803DCA8C + 0x14))(obj, state, 2);
    } else if (mode < 5) {
        *(u8 *)(setup + 0x56) = 0;
        (*(void (*)(int, int, int))(*lbl_803DCA8C + 0x14))(obj, state, 7);
    }

    (*(void (*)(int, int))(*lbl_803DCAA8 + 0x20))(obj, state + 4);
    *(f32 *)(state + 0x294) = lbl_803E8234;
    *(f32 *)(state + 0x284) = lbl_803E8234;
    *(f32 *)(state + 0x280) = lbl_803E8234;
    *(f32 *)(obj + 0x24) = lbl_803E8234;
    *(f32 *)(obj + 0x28) = lbl_803E8234;
    *(f32 *)(obj + 0x2c) = lbl_803E8234;
    return (u32)(-*(s8 *)(setup + 0x56) | *(s8 *)(setup + 0x56)) >> 0x1f;
}
#pragma dont_inline reset

/*
 * fn_802BB648 - 52-instruction helper. Stubbed.
 */
#pragma dont_inline on
void fn_802BB648(void) {}
#pragma dont_inline reset

/*
 * fn_802BB8E4 - 45-instruction helper. Stubbed.
 */
#pragma dont_inline on
void fn_802BB8E4(void) {}
#pragma dont_inline reset

/*
 * fn_802BB998 - 85-instruction helper. Stubbed.
 */
#pragma dont_inline on
void fn_802BB998(void) {}
#pragma dont_inline reset

/*
 * Returns 0xd0c.
 */
int fn_802BBAEC(void) { return 0xd0c; }

/*
 * Returns 0x43.
 */
int fn_802BBAF4(void) { return 0x43; }

/*
 * Wrapper for ObjGroup_RemoveObject(obj, 0xa).
 */
void fn_802BBAFC(int obj)
{
    ObjGroup_RemoveObject(obj, 0xa);
}

/*
 * fn_802BBB20 - 60-instruction helper. Stubbed.
 */
#pragma dont_inline on
void fn_802BBB20(void) {}
#pragma dont_inline reset
