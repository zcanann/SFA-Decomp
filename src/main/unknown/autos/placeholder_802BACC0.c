#include "ghidra_import.h"

extern void GameBit_Set(int eventId, int value);
extern void ObjGroup_RemoveObject(int obj, int group);

extern f32 lbl_803E8234;
extern f32 lbl_803E827C;

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
 * fn_802BB020 — 41-instruction state setup. Stubbed.
 */
#pragma dont_inline on
void fn_802BB020(void) {}
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
 * ddh_cc_initinterrupts — large interrupt-init helper (~140
 * instructions). Stubbed.
 */
#pragma dont_inline on
void ddh_cc_initinterrupts(void) {}
#pragma dont_inline reset

/*
 * fn_802BB648 — 52-instruction helper. Stubbed.
 */
#pragma dont_inline on
void fn_802BB648(void) {}
#pragma dont_inline reset

/*
 * fn_802BB8E4 — 45-instruction helper. Stubbed.
 */
#pragma dont_inline on
void fn_802BB8E4(void) {}
#pragma dont_inline reset

/*
 * fn_802BB998 — 85-instruction helper. Stubbed.
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
 * fn_802BBB20 — 60-instruction helper. Stubbed.
 */
#pragma dont_inline on
void fn_802BBB20(void) {}
#pragma dont_inline reset
