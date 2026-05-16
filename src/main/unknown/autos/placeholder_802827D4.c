#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802827D4.h"

extern u16 _GetInputValue(void *state, void *slot, u8 a, u8 b);
extern int synthGetVoiceSlotChannelScale(int x);
extern u32 inpGetMidiCtrl(u8 controller, u32 slot, u32 key);
extern void inpSetMidiCtrl14(u8 controller, u8 slot, u8 key, u32 value);

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

extern u8 lbl_803BDA74[];
extern u8 lbl_803BDEF4[];
extern u32 lbl_803D3CA0[];
extern u32 lbl_8032FFE0[];

#define MIDI_DIRTY_AUX_BANK_STRIDE 0x10

/*
 * Cached aux A input getter for a studio/channel/slot.
 */
u32 inpGetAuxA(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex)
{
    u32 flags;
    u32 mask;
    u32 tableIndex;

    tableIndex = (handleIndex & 0xff) * MIDI_DIRTY_AUX_BANK_STRIDE + (auxIndex & 0xff);
    flags = lbl_803D3CA0[tableIndex];
    mask = lbl_8032FFE0[channel & 0xff];
    if ((mask & flags) == 0) {
        return *(u16 *)(lbl_803BDEF4 + (studio & 0xff) * 0x90 + (channel & 0xff) * 0x24);
    }
    lbl_803D3CA0[tableIndex] = flags & ~mask;
    return _GetInputValue(0, lbl_803BDEF4 + (channel & 0xff) * 0x24 + (studio & 0xff) * 0x90,
                          0, 0);
}

/*
 * Cached aux B input getter for a studio/channel/slot.
 */
u32 inpGetAuxB(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex)
{
    u32 flags;
    u32 mask;
    u32 tableIndex;

    tableIndex = (handleIndex & 0xff) * MIDI_DIRTY_AUX_BANK_STRIDE + (auxIndex & 0xff);
    flags = lbl_803D3CA0[tableIndex];
    mask = lbl_8032FFE0[(channel & 0xff) + 4];
    if ((mask & flags) == 0) {
        return *(u16 *)(lbl_803BDA74 + (studio & 0xff) * 0x90 + (channel & 0xff) * 0x24);
    }
    lbl_803D3CA0[tableIndex] = flags & ~mask;
    return _GetInputValue(0, lbl_803BDA74 + (channel & 0xff) * 0x24 + (studio & 0xff) * 0x90,
                          0, 0);
}

/*
 * inpInit - input/controller state init.
 *
 * EN v1.0 Address: 0x802829D0
 * EN v1.0 Size: 740b (0x2E4)
 */
void inpInit(u32 state)
{
    if (state != 0) {
        *(u8 *)(state + 0x218) = 7;
        *(u8 *)(state + 0x219) = 0;
        *(u32 *)(state + 0x21c) = 0x10000;
        *(u8 *)(state + 0x220) = 0xb;
        *(u8 *)(state + 0x221) = 2;
        *(u32 *)(state + 0x224) = 0x10000;
        *(u8 *)(state + 0x23a) = 2;
        *(u8 *)(state + 0x23c) = 0xa;
        *(u8 *)(state + 0x23d) = 0;
        *(u32 *)(state + 0x240) = 0x10000;
        *(u8 *)(state + 0x25e) = 1;
        *(u8 *)(state + 0x260) = 0x83;
        *(u8 *)(state + 0x261) = 0;
        *(u32 *)(state + 0x264) = 0x10000;
        *(u8 *)(state + 0x282) = 1;
        *(u8 *)(state + 0x284) = 0x80;
        *(u8 *)(state + 0x285) = 0;
        *(u32 *)(state + 0x288) = 0x10000;
        *(u8 *)(state + 0x2a6) = 1;
        *(u8 *)(state + 0x2cc) = 1;
        *(u8 *)(state + 0x2cd) = 0;
        *(u32 *)(state + 0x2d0) = 0x10000;
        *(u8 *)(state + 0x2ee) = 1;
        *(u8 *)(state + 0x2f0) = 0x40;
        *(u8 *)(state + 0x2f1) = 0;
        *(u32 *)(state + 0x2f4) = 0x10000;
        *(u8 *)(state + 0x312) = 1;
        *(u8 *)(state + 0x314) = 0x41;
        *(u8 *)(state + 0x315) = 0;
        *(u32 *)(state + 0x318) = 0x10000;
        *(u8 *)(state + 0x336) = 1;
        *(u8 *)(state + 0x35a) = 0;
        *(u8 *)(state + 0x35c) = 0x5b;
        *(u8 *)(state + 0x35d) = 0;
        *(u32 *)(state + 0x360) = 0x10000;
        *(u8 *)(state + 0x37e) = 1;
        *(u8 *)(state + 0x3a2) = 0;
        *(u8 *)(state + 0x3a4) = 0x5d;
        *(u8 *)(state + 0x3a5) = 0;
        *(u32 *)(state + 0x3a8) = 0x10000;
        *(u8 *)(state + 0x3c6) = 1;
        *(u8 *)(state + 0x2a8) = 0x84;
        *(u8 *)(state + 0x2a9) = 0;
        *(u32 *)(state + 0x2ac) = 0x10000;
        *(u8 *)(state + 0x2ca) = 1;
        *(u8 *)(state + 0x3ea) = 0;
        *(u32 *)(state + 0x214) = 0x1fff;
        *(u8 *)(state + 0x1d4) = 0;
        *(u8 *)(state + 0x1d5) = 0;
        *(u8 *)(state + 0xa8) = 0;
    } else {
        int i;
        u8 *b = lbl_803BDA74;
        u8 *a = lbl_803BDEF4;
        u32 *p = lbl_803D3CA0;

        a[0x22] = 0;  b[0x22] = 0;
        a[0x46] = 0;  b[0x46] = 0;
        a[0x6a] = 0;  b[0x6a] = 0;
        a[0x8e] = 0;  b[0x8e] = 0;
        a[0xb2] = 0;  b[0xb2] = 0;
        a[0xd6] = 0;  b[0xd6] = 0;
        a[0xfa] = 0;  b[0xfa] = 0;
        a[0x11e] = 0; b[0x11e] = 0;
        a[0x142] = 0; b[0x142] = 0;
        a[0x166] = 0; b[0x166] = 0;
        a[0x18a] = 0; b[0x18a] = 0;
        a[0x1ae] = 0; b[0x1ae] = 0;
        a[0x1d2] = 0; b[0x1d2] = 0;
        a[0x1f6] = 0; b[0x1f6] = 0;
        a[0x21a] = 0; b[0x21a] = 0;
        a[0x23e] = 0; b[0x23e] = 0;
        a[0x262] = 0; b[0x262] = 0;
        a[0x286] = 0; b[0x286] = 0;
        a[0x2aa] = 0; b[0x2aa] = 0;
        a[0x2ce] = 0; b[0x2ce] = 0;
        a[0x2f2] = 0; b[0x2f2] = 0;
        a[0x316] = 0; b[0x316] = 0;
        a[0x33a] = 0; b[0x33a] = 0;
        a[0x35e] = 0; b[0x35e] = 0;
        a[0x382] = 0; b[0x382] = 0;
        a[0x3a6] = 0; b[0x3a6] = 0;
        a[0x3ca] = 0; b[0x3ca] = 0;
        a[0x3ee] = 0; b[0x3ee] = 0;
        a[0x412] = 0; b[0x412] = 0;
        a[0x436] = 0; b[0x436] = 0;
        a[0x45a] = 0; b[0x45a] = 0;
        a[0x47e] = 0; b[0x47e] = 0;

        for (i = 0; i < 4; i++) {
            p[0] = 0xff;  p[1] = 0xff;  p[2] = 0xff;  p[3] = 0xff;
            p[4] = 0xff;  p[5] = 0xff;  p[6] = 0xff;  p[7] = 0xff;
            p[8] = 0xff;  p[9] = 0xff;  p[10] = 0xff; p[11] = 0xff;
            p[12] = 0xff; p[13] = 0xff; p[14] = 0xff; p[15] = 0xff;
            p += 16;
            p[0] = 0xff;  p[1] = 0xff;  p[2] = 0xff;  p[3] = 0xff;
            p[4] = 0xff;  p[5] = 0xff;  p[6] = 0xff;  p[7] = 0xff;
            p[8] = 0xff;  p[9] = 0xff;  p[10] = 0xff; p[11] = 0xff;
            p[12] = 0xff; p[13] = 0xff; p[14] = 0xff; p[15] = 0xff;
            p += 16;
        }
    }
}

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

/*
 * Read an extended controller value, with local state-backed overrides for
 * translated controller 0xA0/0xA1.
 */
u32 inpGetExCtrl(int state, u32 ctrl)
{
    u8 translated;
    u32 value;

    translated = inpTranslateExCtrl(ctrl);
    if (translated == 0xa1) {
        value = *(s16 *)(state + 0x1d0) * 2 + 0x2000;
    } else if (translated < 0xa1 && translated > 0x9f) {
        value = *(s16 *)(state + 0x1c4) * 2 + 0x2000;
    } else if (*(s8 *)(state + 0x121) == -1) {
        value = 0;
    } else {
        value = inpGetMidiCtrl(ctrl, *(u8 *)(state + 0x121), *(u8 *)(state + 0x122));
        value &= 0xffff;
    }
    return value;
}

/*
 * Clamp and write an extended controller through MIDI for non-local controls.
 */
void inpSetExCtrl(int state, u32 ctrl, s16 value)
{
    u8 translated;

    if (value < 0) {
        value = 0;
    } else if (value > 0x3fff) {
        value = 0x3fff;
    }
    translated = inpTranslateExCtrl(ctrl);
    if ((translated > 0xa1 || translated < 0xa0) && *(s8 *)(state + 0x121) != -1) {
        inpSetMidiCtrl14(ctrl, *(u8 *)(state + 0x121), *(u8 *)(state + 0x122), (int)value);
    }
}

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

/*
 * Binary search over fixed-stride sorted table entries.
 */
void *sndBSearch(void *key, void *base, u16 count, u32 stride, int (*cmp)(void *, void *))
{
    int low;
    int mid;
    int high;
    void *entry;
    int result;

    if (count != 0) {
        low = 1;
        high = count;
        do {
            mid = (low + high) >> 1;
            entry = (u8 *)base + stride * (mid - 1);
            result = cmp(key, entry);
            if (result == 0) {
                return entry;
            }
            if (result > -1) {
                low = mid + 1;
                mid = high;
            }
            high = mid;
        } while (low <= high);
    }
    return 0;
}

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
    int div = synthGetVoiceSlotChannelScale(x);
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
