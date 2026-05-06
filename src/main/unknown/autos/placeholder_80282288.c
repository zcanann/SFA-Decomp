#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80282288.h"

/*
 * fn_80282070 — large MIDI/sample event dispatcher (~344 instructions);
 * called by all the bit-flag accessor functions in placeholders
 * 80282630 / 80282288. Stubbed here so callers compile.
 */
#pragma dont_inline on
u16 fn_80282070(void *state, void *slot, u8 a, u8 b)
{
    (void)state;
    (void)slot;
    (void)a;
    (void)b;
    return 0;
}
#pragma dont_inline reset

/*
 * Bit-1 (mask 0x1) accessor — slot at +0x218, cached u16 at +0x238.
 *
 * EN v1.0 Address: 0x80282078
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802824F8
 * EN v1.1 Size: 72b
 */
u16 fn_802824F8(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x1) == 0) {
        return *(u16 *)(state + 0x238);
    }
    *(u32 *)(state + 0x214) = flags & ~0x1;
    return fn_80282070((void *)state, (void *)(state + 0x218),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/*
 * Bit-2 (mask 0x2) accessor — slot at +0x23c, cached u16 at +0x25c.
 *
 * EN v1.1 Address: 0x80282540
 * EN v1.1 Size: 72b
 */
u16 fn_80282540(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x2) == 0) {
        return *(u16 *)(state + 0x25c);
    }
    *(u32 *)(state + 0x214) = flags & ~0x2;
    return fn_80282070((void *)state, (void *)(state + 0x23c),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}
