#include "ghidra_import.h"

extern int fn_8027A660(int state);

extern u16 lbl_8032F618[];

/*
 * Advance an ADSR envelope state machine: phase 0 = attack setup,
 * 1 = decay setup, 2 = sustain setup, 4 = done. Mode 1 scales levels
 * by the 0xC1-step volume curve.
 */
#pragma dont_inline on
int fn_8027A660(int state)
{
    int ret = 0;

    switch (*(u8 *)state) {
    case 0:
        switch (*(u8 *)(state + 1)) {
        case 0:
            if ((*(u32 *)(state + 4) = *(u32 *)(state + 0x14)) != 0) {
                *(u8 *)(state + 1) = 1;
                *(u32 *)(state + 8) = 0;
                *(u32 *)(state + 0x10) = 0x7fff0000 / *(u32 *)(state + 0x14);
                break;
            }
            /* fall through */
        case 1:
            if ((*(u32 *)(state + 4) = *(u32 *)(state + 0x18)) != 0) {
                *(u8 *)(state + 1) = 2;
                *(u32 *)(state + 8) = 0x7fff0000;
                *(u32 *)(state + 0x10) =
                    -((0x7fff0000 - (*(u16 *)(state + 0x1c) << 16)) / *(u32 *)(state + 0x18));
                break;
            }
            /* fall through */
        case 2:
            if (*(u16 *)(state + 0x1c) != 0) {
                *(u8 *)(state + 1) = 3;
                *(u32 *)(state + 8) = *(u16 *)(state + 0x1c) << 16;
                *(u32 *)(state + 0x10) = 0;
                break;
            }
            /* fall through */
        case 4:
            *(u32 *)(state + 8) = 0;
            ret = 1;
            break;
        }
        break;
    case 1:
        switch (*(u8 *)(state + 1)) {
        case 0:
            if ((*(u32 *)(state + 4) = *(u32 *)(state + 0x14)) != 0) {
                *(u8 *)(state + 1) = 1;
                if (*(u8 *)(state + 0x26) == 0) {
                    *(u32 *)(state + 8) = 0;
                    *(u32 *)(state + 0x10) = 0x7fff0000 / *(u32 *)(state + 4);
                } else {
                    *(u32 *)(state + 0xc) = 0;
                    *(u32 *)(state + 8) = 0;
                    *(u32 *)(state + 0x10) = 0xc10000 / *(u32 *)(state + 4);
                }
                break;
            }
            /* fall through */
        case 1:
            *(u32 *)(state + 4) =
                *(u32 *)(state + 0x18) * (((0xc1 - (u32)*(u16 *)(state + 0x1c)) << 16) / 0xc1) >> 16;
            if (*(u32 *)(state + 4) != 0) {
                *(u8 *)(state + 1) = 2;
                *(u32 *)(state + 8) = 0x7fff0000;
                *(u32 *)(state + 0xc) = 0xc10000;
                *(u32 *)(state + 0x10) =
                    -(((0xc1 - (u32)*(u16 *)(state + 0x1c)) << 16) / *(u32 *)(state + 4));
                break;
            }
            /* fall through */
        case 2:
            if (*(u16 *)(state + 0x1c) != 0) {
                int idx;

                *(u8 *)(state + 1) = 3;
                *(u32 *)(state + 0xc) = *(u16 *)(state + 0x1c) << 16;
                if ((idx = 0xc1 - ((*(s32 *)(state + 0xc) + 0x8000) >> 16)) < 0) {
                    idx = 0;
                }
                *(u32 *)(state + 8) = lbl_8032F618[idx] << 16;
                *(u32 *)(state + 0x10) = 0;
                break;
            }
            /* fall through */
        case 4:
            *(u32 *)(state + 8) = 0;
            ret = 1;
            break;
        }
        break;
    }
    return ret;
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
