#include "ghidra_import.h"

/*
 * fn_802800C0 — large reverb/effect chain init (~840 instructions).
 * Stubbed.
 */
#pragma dont_inline on
void fn_802800C0(void) {}
#pragma dont_inline reset

/*
 * fn_802805A4 — 540-instr per-voice update. Stubbed.
 */
#pragma dont_inline on
void fn_802805A4(void) {}
#pragma dont_inline reset

/*
 * fn_802807C4 — 276-instr voice slot allocator. Stubbed.
 */
#pragma dont_inline on
int fn_802807C4(int state, float f1)
{
    (void)state; (void)f1;
    return 0;
}
#pragma dont_inline reset

/*
 * fn_802808D8 — 304-instr voice node insert. Stubbed.
 */
#pragma dont_inline on
int fn_802808D8(int state, float f1, float f2, float f3, float f4, float f5)
{
    (void)state; (void)f1; (void)f2; (void)f3; (void)f4; (void)f5;
    return 0;
}
#pragma dont_inline reset

/*
 * fn_80280A08 — 552-instr voice list walker with FP math. Stubbed.
 */
#pragma dont_inline on
void fn_80280A08(void) {}
#pragma dont_inline reset
