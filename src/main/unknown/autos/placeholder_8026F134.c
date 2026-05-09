#include "ghidra_import.h"

extern u8 lbl_803BCD90[];

/*
 * fn_8026EC44 - large pre-pitch processing (~1736 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026EC44(void) {}
#pragma dont_inline reset

/*
 * fn_8026F30C - 560-instr voice param helper. Stubbed.
 */
#pragma dont_inline on
void fn_8026F30C(void) {}
#pragma dont_inline reset

/*
 * fn_8026F53C - magic-divide table store (~72 instructions). Stubbed.
 */
void fn_8026F53C(int value, u8 bank, u32 key)
{
    if (bank == 0xff) {
        bank = 8;
    }
    *(u32 *)(lbl_803BCD90 + (key & 0xff) * 4 + bank * 0x40) =
        (u32)(value * 0x3000) / 0xf0;
}

/*
 * Look up an int from a 2D table indexed by state's ID bytes.
 *
 * EN v1.1 Address: 0x8026F584, size 52b
 */
int fn_8026F584(int state)
{
    u32 a = *(u8 *)(state + 0x122);
    int b;
    if (a == 0xff) a = 8;
    b = *(u8 *)(state + 0x123);
    return *(int *)(lbl_803BCD90 + a * 64 + b * 4);
}

/*
 * fn_8026F5B8 - flag-check and conditional store (~120 instructions).
 * Stubbed.
 */
void fn_8026F5B8(int state)
{
    if ((*(u32 *)(state + 0x118) & 0x20000) != 0) {
        return;
    }
    if (*(s8 *)(state + 0x131) == 1) {
        if ((*(u32 *)(state + 0x118) & 0x1000) == 0) {
            *(u32 *)(state + 0x13c) = 0;
        } else {
            *(u32 *)(state + 0x13c) = *(u32 *)(state + 0x134);
        }
    } else {
        *(u32 *)(state + 0x13c) = *(u32 *)(state + 0x134);
    }
    *(u32 *)(state + 0x138) = (u32)*(u8 *)(state + 0x130) << 0x10;
}

/*
 * audioFn_8026f630 - 648-instr per-voice update loop. Stubbed.
 */
#pragma dont_inline on
void audioFn_8026f630(void) {}
#pragma dont_inline reset
