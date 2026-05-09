#include "ghidra_import.h"

extern u8 synthVirtualSampleState[];

/*
 * Reset a 64-byte handle table at synthVirtualSampleState+0x908 to all-0xff,
 * along with surrounding metadata.
 *
 * EN v1.1 Address: 0x8027ACB8, size 288b
 */
void synthInitVirtualSampleTable(void)
{
    int i;
    synthVirtualSampleState[0] = 0;
    for (i = 0; i < 64; i++) {
        synthVirtualSampleState[0x908 + i] = 0xff;
    }
    *(u16 *)(synthVirtualSampleState + 0x948) = 0;
    *(u32 *)(synthVirtualSampleState + 0x94c) = 0;
}

/*
 * synthClaimVirtualSampleSlot - voice-allocate-and-set-loop helper
 * (~488 instructions).
 * Stubbed.
 */
#pragma dont_inline on
int synthClaimVirtualSampleSlot(u8 a)
{
    (void)a;
    return 0;
}
#pragma dont_inline reset
