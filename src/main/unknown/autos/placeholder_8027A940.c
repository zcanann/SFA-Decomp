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

extern u16 lbl_8032F618[];

#pragma dont_inline on
int fn_8027AA94(int state, u16 *out1, u16 *out2)
{
    int ret = 0;
    int m = *(u8 *)state;
    int v8;
    int idx;
    u16 o;

    if (m != 1) {
        if (m < 1) {
            if (m < 0) {
            } else {
                if (*(u8 *)(state + 1) != 3) {
                    v8 = *(int *)(state + 8);
                    *(int *)(state + 8) = v8 + *(int *)(state + 0x10);
                    o = v8 >> 16;
                    *out1 = o;
                    if (*(int *)(state + 0x10) >= 0) {
                        o = *(int *)(state + 0x10) >> 21;
                        *out2 = o;
                    } else {
                        o = -(-*(int *)(state + 0x10) >> 21);
                        *out2 = o;
                    }
                    if (--*(int *)(state + 4) == 0) {
                        ret = fn_8027A660(state);
                    }
                } else {
                    o = *(int *)(state + 8) >> 16;
                    *out1 = o;
                    *out2 = 0;
                }
            }
        }
    } else {
        if (*(u8 *)(state + 1) != 3) {
            v8 = *(int *)(state + 8);
            if (*(u8 *)(state + 0x26) == 0 && *(u8 *)(state + 1) == 1) {
                *(int *)(state + 8) = v8 + *(int *)(state + 0x10);
            } else {
                *(int *)(state + 0xc) = *(int *)(state + 0xc) + *(int *)(state + 0x10);
                idx = 193 - ((*(int *)(state + 0xc) + 0x8000) >> 16);
                if (idx < 0) {
                    idx = 0;
                }
                *(int *)(state + 8) = lbl_8032F618[idx] << 16;
            }
            o = v8 >> 16;
            *out1 = o;
            if (*(int *)(state + 8) - v8 >= 0) {
                o = (*(int *)(state + 8) - v8) >> 21;
                *out2 = o;
            } else {
                o = -(-(*(int *)(state + 8) - v8) >> 21);
                *out2 = o;
            }
            if (--*(int *)(state + 4) == 0) {
                ret = fn_8027A660(state);
            }
        } else {
            o = *(int *)(state + 8) >> 16;
            *out1 = o;
            *out2 = 0;
        }
    }
    return ret;
}
#pragma dont_inline reset
