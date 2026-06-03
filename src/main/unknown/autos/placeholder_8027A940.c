#include "ghidra_import.h"

extern int fn_8027A8FC(int state, u32 divisor);
extern int fn_8027A660(int state);

extern u8 voiceAdsrDecayTable[];
extern f32 lbl_803E7848;

#pragma dont_inline on
int fn_8027A8FC(int state, u32 divisor)
{
    int m = *(u8 *)state;
    if (m != 1) {
        if (m < 1) {
            if (m >= 0) {
                *(u8 *)(state + 1) = 4;
                *(u32 *)(state + 4) = divisor;
                if (divisor == 0) {
                    *(u32 *)(state + 4) = 1;
                    *(u32 *)(state + 0x10) = 0;
                    return 1;
                }
                *(u32 *)(state + 0x10) = -(*(u32 *)(state + 8) / divisor);
            }
        }
    } else {
        if (*(u8 *)(state + 0x26) == 0 && *(u8 *)(state + 1) == 1) {
            *(u32 *)(state + 0xc) = (u32)(193 - voiceAdsrDecayTable[*(int *)(state + 8) >> 21]) << 16;
        }
        *(u32 *)(state + 4) = (u32)(lbl_803E7848 * (f32)*(int *)(state + 0xc) * (f32)divisor) >> 12;
        *(u8 *)(state + 1) = 4;
        if (*(u32 *)(state + 4) == 0) {
            *(u32 *)(state + 4) = 1;
            *(u32 *)(state + 8) = 0;
            *(u32 *)(state + 0xc) = 0;
            *(u32 *)(state + 0x10) = 0;
            return 1;
        }
        *(u32 *)(state + 0x10) = -(*(u32 *)(state + 0xc) / *(u32 *)(state + 4));
    }
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
