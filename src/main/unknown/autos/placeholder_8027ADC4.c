#include "ghidra_import.h"

extern u8 lbl_803CB290[];

/*
 * Reset a 64-byte handle table at lbl_803CB290+0x908 to all-0xff,
 * along with surrounding metadata.
 *
 * EN v1.1 Address: 0x8027ACB8, size 288b
 */
void fn_8027ACB8(void)
{
    int i;
    lbl_803CB290[0] = 0;
    for (i = 0; i < 64; i++) {
        lbl_803CB290[0x908 + i] = 0xff;
    }
    *(u16 *)(lbl_803CB290 + 0x948) = 0;
    *(u32 *)(lbl_803CB290 + 0x94c) = 0;
}

/*
 * fn_8027ADD8 — voice-allocate-and-set-loop helper (~488 instructions).
 * Stubbed.
 */
#pragma dont_inline on
int fn_8027ADD8(u8 a)
{
    (void)a;
    return 0;
}
#pragma dont_inline reset
