#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027641C.h"

extern u8 *fn_80275058(u16 keyId);
extern void fn_80282F80(u32 *p);
extern void fn_80282F90(u32 *p, void *state);
extern int fn_80282FD8(u32 v);

/*
 * Linear-interpolated table lookup: value's high u16 selects entry,
 * low u16 is the fractional weight between entry[hi] and entry[hi+1].
 *
 * EN v1.0 Address: 0x802763C0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027641C
 * EN v1.1 Size: 124b
 */
u32 fn_802763C0(u32 value, u16 keyId)
{
    u32 result = value;
    if (keyId != 0xffff) {
        u8 *table = fn_80275058(keyId);
        if (table != NULL) {
            u32 hi = result >> 16;
            u32 lo = result & 0xffff;
            if (hi < 0x7f) {
                u32 a = table[hi];
                u32 b = table[hi + 1];
                result = (a << 16) + lo * (b - a);
            } else {
                result = (u32)table[hi] << 16;
            }
        }
    }
    return result;
}

/*
 * Compute envelope step: scale + interpolate via table, store target/
 * time/step into state, mark state dirty.
 *
 * EN v1.0 Address: 0x80276440
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80276440
 * EN v1.1 Size: 296b
 */
void fn_80276440(int state, u32 *params, u32 timeArg)
{
    u32 t;
    int divisor;
    u32 scaled;
    u16 keyId;
    u8 *table;

    t = params[1] >> 16;
    if ((params[1] >> 8) & 1) {
        fn_80282F80(&t);
    } else {
        fn_80282F90(&t, (void *)state);
    }
    divisor = fn_80282FD8(t);
    if (divisor == 0) {
        divisor = 1;
    }

    {
        u32 p0 = params[0];
        u32 hi = (p0 >> 16) & 0xff;
        scaled = (*(u32 *)(state + 0x154) * hi) >> 7;
        scaled += (p0 & 0xff00);
        if (scaled > 0x7f0000) {
            scaled = 0x7f0000;
        }
        keyId = (u16)((p0 >> 24) | ((params[1] & 0xff) << 8));
    }

    if (keyId != 0xffff) {
        table = fn_80275058(keyId);
        if (table != NULL) {
            u32 hi = scaled >> 16;
            u32 lo = scaled & 0xffff;
            if (hi >= 0x7f) {
                scaled = (u32)table[hi] << 16;
            } else {
                u32 a = table[hi];
                u32 b = table[hi + 1];
                scaled = (a << 16) + lo * (b - a);
            }
        }
    }

    *(u32 *)(state + 0x198) = scaled;
    *(u32 *)(state + 0x19c) = timeArg;
    *(u32 *)(state + 0x194) = (s32)(scaled - timeArg) / divisor;
    *(u32 *)(state + 0x154) = timeArg;
    *(u32 *)(state + 0x118) |= 0x8000;
}
