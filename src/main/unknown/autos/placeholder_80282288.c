#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80282288.h"

/*
 * _GetInputValue - large MIDI/sample event dispatcher called by the
 * cached controller accessors. Stubbed here so callers compile.
 */
#pragma dont_inline on
u16 _GetInputValue(void *state, void *slot, u8 a, u8 b)
{
    (void)state;
    (void)slot;
    (void)a;
    (void)b;
    return 0;
}
#pragma dont_inline reset

/*
 * Volume accessor: bit 0x1, slot at +0x218, cached u16 at +0x238.
 *
 * EN v1.0 Address: 0x80282078
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802824F8
 * EN v1.1 Size: 72b
 */
u16 inpGetVolume(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x1) == 0) {
        return *(u16 *)(state + 0x238);
    }
    *(u32 *)(state + 0x214) = flags & ~0x1;
    return _GetInputValue((void *)state, (void *)(state + 0x218),
                          *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/*
 * Panning accessor: bit 0x2, slot at +0x23c, cached u16 at +0x25c.
 *
 * EN v1.1 Address: 0x80282540
 * EN v1.1 Size: 72b
 */
u16 inpGetPanning(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x2) == 0) {
        return *(u16 *)(state + 0x25c);
    }
    *(u32 *)(state + 0x214) = flags & ~0x2;
    return _GetInputValue((void *)state, (void *)(state + 0x23c),
                          *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}
