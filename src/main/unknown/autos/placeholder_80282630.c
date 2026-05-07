#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80282630.h"

extern u16 _GetInputValue(void *state, void *slot, u8 a, u8 b);

/*
 * --INFO--
 *
 * Function: inpGetDoppler
 * EN v1.0 Address: 0x80282618
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80282630
 * EN v1.1 Size: 72b
 */
u16 inpGetDoppler(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x10) == 0) {
        return *(u16 *)(state + 0x2c8);
    }
    *(u32 *)(state + 0x214) = flags & ~0x10;
    return _GetInputValue((void *)state, (void *)(state + 0x2a8),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/*
 * Function: inpGetModulation
 */
u16 inpGetModulation(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x20) == 0) {
        return *(u16 *)(state + 0x2ec);
    }
    *(u32 *)(state + 0x214) = flags & ~0x20;
    return _GetInputValue((void *)state, (void *)(state + 0x2cc),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/*
 * Function: inpGetPedal
 */
u16 inpGetPedal(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x40) == 0) {
        return *(u16 *)(state + 0x310);
    }
    *(u32 *)(state + 0x214) = flags & ~0x40;
    return _GetInputValue((void *)state, (void *)(state + 0x2f0),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/*
 * Function: inpGetPreAuxA
 */
u16 inpGetPreAuxA(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x100) == 0) {
        return *(u16 *)(state + 0x358);
    }
    *(u32 *)(state + 0x214) = flags & ~0x100;
    return _GetInputValue((void *)state, (void *)(state + 0x338),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/*
 * Function: inpGetReverb
 */
u16 inpGetReverb(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x200) == 0) {
        return *(u16 *)(state + 0x37c);
    }
    *(u32 *)(state + 0x214) = flags & ~0x200;
    return _GetInputValue((void *)state, (void *)(state + 0x35c),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/*
 * Function: inpGetPreAuxB
 */
u16 inpGetPreAuxB(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x400) == 0) {
        return *(u16 *)(state + 0x3a0);
    }
    *(u32 *)(state + 0x214) = flags & ~0x400;
    return _GetInputValue((void *)state, (void *)(state + 0x380),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}
