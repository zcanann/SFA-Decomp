#include "ghidra_import.h"

extern int fn_8027A8FC(int state, int divisor);
extern int fn_8027A660(int state);

/*
 * fn_8027A8FC — pitch envelope setup with FP math (~340 instructions).
 * Stubbed.
 */
#pragma dont_inline on
int fn_8027A8FC(int state, int divisor)
{
    (void)state; (void)divisor;
    return 0;
}
#pragma dont_inline reset

/*
 * Wrapper for fn_8027A8FC: dispatches when state mode is 0 or 1.
 *
 * EN v1.1 Address: 0x8027AA50, size 68b
 */
int fn_8027AA50(int state)
{
    switch (*(u8 *)(state + 0)) {
    case 0:
    case 1:
        return fn_8027A8FC(state, *(int *)(state + 0x20));
    }
    return 0;
}

/*
 * fn_8027AA94 — pitch state advance with output writeback (~416
 * instructions, switch on mode 0/1, lookup table indexing). Stubbed.
 */
#pragma dont_inline on
int fn_8027AA94(int state, s16 *out1, s16 *out2)
{
    (void)state; (void)out1; (void)out2;
    return 0;
}
#pragma dont_inline reset
