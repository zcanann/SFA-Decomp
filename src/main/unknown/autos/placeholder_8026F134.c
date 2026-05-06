#include "ghidra_import.h"

extern u8 lbl_803BCD90[];

/*
 * fn_8026EC44 — large pre-pitch processing (~1736 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026EC44(void) {}
#pragma dont_inline reset

/*
 * fn_8026F30C — 560-instr voice param helper. Stubbed.
 */
#pragma dont_inline on
void fn_8026F30C(void) {}
#pragma dont_inline reset

/*
 * fn_8026F53C — magic-divide table store (~72 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026F53C(int a, u8 b, u8 c)
{
    (void)a; (void)b; (void)c;
}
#pragma dont_inline reset

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
 * fn_8026F5B8 — flag-check and conditional store (~120 instructions).
 * Stubbed.
 */
#pragma dont_inline on
void fn_8026F5B8(int state)
{
    (void)state;
}
#pragma dont_inline reset

/*
 * fn_8026F630 — 648-instr per-voice update loop. Stubbed.
 */
#pragma dont_inline on
void fn_8026F630(void) {}
#pragma dont_inline reset
