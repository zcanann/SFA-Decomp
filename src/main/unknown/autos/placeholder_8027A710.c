#include "ghidra_import.h"

extern int fn_8027A660(int state);

/*
 * fn_8027A660 — large envelope state-machine advance with mode/submode
 * dispatch (~628 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_8027A660(int state)
{
    (void)state;
    return 0;
}
#pragma dont_inline reset

/*
 * Reset state's submode and call fn_8027A660.
 *
 * EN v1.1 Address: 0x8027A8D4, size 40b
 */
int fn_8027A8D4(int state)
{
    *(u8 *)(state + 1) = 0;
    return fn_8027A660(state);
}
