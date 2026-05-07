#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802827D4.h"

extern u16 _GetInputValue(void *state, void *slot, u8 a, u8 b);
extern int fn_8026F584(int x);

extern u32 lbl_803DC610;
extern s16 lbl_80330028[];

/*
 * Bit-11 (0x800) accessor - slot at +0x3a4, cached u16 at +0x3c4.
 *
 * EN v1.1 Address: 0x802827C8, size 72b
 */
u16 inpGetPostAuxB(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x800) == 0) {
        return *(u16 *)(state + 0x3c4);
    }
    *(u32 *)(state + 0x214) = flags & ~0x800;
    return _GetInputValue((void *)state, (void *)(state + 0x3a4),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/*
 * Bit-12 (0x1000) accessor - slot at +0x3c8, cached u16 at +0x3e8.
 *
 * EN v1.1 Address: 0x80282810, size 72b
 */
u16 inpGetTremolo(int state)
{
    u32 flags = *(u32 *)(state + 0x214);
    if ((flags & 0x1000) == 0) {
        return *(u16 *)(state + 0x3e8);
    }
    *(u32 *)(state + 0x214) = flags & ~0x1000;
    return _GetInputValue((void *)state, (void *)(state + 0x3c8),
                       *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
}

/* inpGetAuxA - aux A getter. Stubbed. */
#pragma dont_inline on
void inpGetAuxA(void) {}
#pragma dont_inline reset

/* inpGetAuxB - aux B getter. Stubbed. */
#pragma dont_inline on
void inpGetAuxB(void) {}
#pragma dont_inline reset

/* inpInit - input/controller state init. Stubbed. */
#pragma dont_inline on
void inpInit(void) {}
#pragma dont_inline reset

/*
 * Map an input byte (0x80..0x88) to a packed table value via a
 * jumptable, falling through for inputs outside that range.
 *
 * EN v1.1 Address: 0x80282CB4, size 112b
 */
u32 inpTranslateExCtrl(u32 input)
{
    u32 value = input & 0xff;
    u32 idx = value - 0x80;
    switch (idx) {
    case 0: return 0x80;
    case 1: return 0x82;
    case 2: return 0xa0;
    case 3: return 0xa1;
    case 4: return 0x83;
    case 5: return 0x84;
    case 6: return 0xa2;
    case 7: return 0xa3;
    case 8: return 0xa4;
    default: return input;
    }
}

/* inpGetExCtrl - extended controller getter. Stubbed. */
#pragma dont_inline on
void inpGetExCtrl(void) {}
#pragma dont_inline reset

/* inpSetExCtrl - extended controller setter. Stubbed. */
#pragma dont_inline on
void inpSetExCtrl(void) {}
#pragma dont_inline reset

/*
 * Pseudo-random number generator (linear congruential).
 *
 * EN v1.1 Address: 0x80282E5C, size 32b
 */
u16 sndRand(void)
{
    lbl_803DC610 = lbl_803DC610 * 0xA8351D63U;
    return (u16)((lbl_803DC610 >> 6) & 0xffff);
}

/*
 * Look up s16 from a 4-zone table based on the input's low 12 bits.
 * Upper two zones return sign-flipped values.
 *
 * EN v1.1 Address: 0x80282E7C, size 108b
 */
s16 sndSin(u32 packed)
{
    u32 zone = packed & 0xfff;
    if (zone < 0x400) {
        return *(s16 *)((u8 *)lbl_80330028 + zone * 2);
    }
    if (zone < 0x800) {
        u32 idx = 0x3ff - (zone & 0x3ff);
        return *(s16 *)((u8 *)lbl_80330028 + idx * 2);
    }
    if (zone < 0xc00) {
        u32 idx = (zone & 0x3ff);
        return -*(s16 *)((u8 *)lbl_80330028 + idx * 2);
    }
    {
        u32 idx = 0x3ff - (zone & 0x3ff);
        return -*(s16 *)((u8 *)lbl_80330028 + idx * 2);
    }
}

/* sndBSearch - table binary-search helper. Stubbed. */
#pragma dont_inline on
void sndBSearch(void) {}
#pragma dont_inline reset

/*
 * Shift the value at *p left by 8 bits.
 *
 * EN v1.1 Address: 0x80282F80, size 16b
 */
void sndConvertMs(u32 *p)
{
    *p = *p << 8;
}

/*
 * Compute a normalized scaled-1000-divided-by-32 value at *p using a
 * helper-derived divisor.
 *
 * EN v1.1 Address: 0x80282F90, size 72b
 */
void sndConvertTicks(u32 *p, int x)
{
    int div = fn_8026F584(x);
    *p = (((*p << 16) / div) * 0x3e8) >> 5;
}

/*
 * Right-shift by 8 (truncate ramp index).
 *
 * EN v1.1 Address: 0x80282FD8, size 8b
 */
u32 sndConvert2Ms(u32 x)
{
    return x >> 8;
}
