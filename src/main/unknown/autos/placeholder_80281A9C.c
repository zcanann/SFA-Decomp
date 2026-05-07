#include "ghidra_import.h"

extern void *memcpy(void *dst, const void *src, u32 n);
extern void fn_80281FE8(u8 a, u8 b, u8 v);
extern int fn_80282CB4(int input);

extern u8 lbl_802C2710[];
extern u8 lbl_802C2798[];
extern u8 lbl_803CD760[][16];
extern u8 lbl_803CD7E0[];
extern u8 lbl_803CD820[];
extern u8 lbl_803D1B20[];
extern u8 lbl_803D3EA0[][16];
extern u8 lbl_803D3F20[];

/*
 * Reset a MIDI-controller/default table from one of two preset banks,
 * then mark the controller dirty via fn_80281FE8.
 *
 * EN v1.1 Address: 0x80281A30, size 244b
 */
void inpResetMidiCtrl(u8 a, u8 b, int mode)
{
    u8 *src;
    u8 *dst;

    if (mode != 0) {
        src = lbl_802C2710;
    } else {
        src = lbl_802C2798;
    }

    if (b != 0xff) {
        dst = lbl_803CD820 + b * 0x860 + a * 0x86;
    } else {
        dst = lbl_803D1B20 + a * 0x86;
    }

    if (mode != 0) {
        memcpy(dst, src, 0x86);
    } else {
        int i;
        for (i = 0; i < 0x43; i++) {
            if (*src != 0xff) *dst = *src;
            dst++; src++;
            if (*src != 0xff) *dst = *src;
            dst++; src++;
        }
    }

    fn_80281FE8(a, b, 0xff);
}

/*
 * fn_80281B24 - large multi-case lookup (~652 instructions). Stubbed.
 */
#pragma dont_inline on
u32 fn_80281B24(u8 r3, u8 r4, u8 r5)
{
    (void)r3; (void)r4; (void)r5;
    return 0;
}
#pragma dont_inline reset

/*
 * Returns pointer into either 1D or 2D voice-state table.
 *
 * EN v1.1 Address: 0x80281DB0, size 60b
 */
u8 *fn_80281DB0(u8 a, u8 b)
{
    if (b == 0xff) {
        return &lbl_803D3F20[a];
    }
    return &lbl_803D3EA0[b][a];
}

/*
 * Stores 2 into voice-state slot (1D or 2D variant).
 *
 * EN v1.1 Address: 0x80281DEC, size 68b
 */
void fn_80281DEC(u8 a, u8 b)
{
    u8 *p;
    if (b != 0xff) {
        p = &lbl_803D3EA0[b][a];
    } else {
        p = &lbl_803D3F20[a];
    }
    *p = 2;
}

/*
 * Push an event onto a 4-slot ring at obj+0x22. Resets counter when
 * the input flag (d) is zero. Slot layout: [b, d|0x10 or transformed
 * b, _, _, c, _, _, _].
 *
 * EN v1.1 Address: 0x80281E30, size 156b
 */
void fn_80281E30(int obj, int b, int c, int d, u32 flag)
{
    u8 counter;
    if ((d & 0xff) == 0) {
        *(u8 *)(obj + 0x22) = 0;
    }
    counter = *(u8 *)(obj + 0x22);
    if (counter < 4) {
        *(u8 *)(obj + 0x22) = counter + 1;
        if (flag == 0) {
            b = fn_80282CB4(b);
        } else {
            d |= 0x10;
        }
        *(u8 *)(obj + counter * 8) = (u8)b;
        *(u8 *)(obj + counter * 8 + 1) = (u8)d;
        *(int *)(obj + counter * 8 + 4) = c;
    }
}

/*
 * fn_80281ECC - large multi-case copy (~284 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80281ECC(u8 r3, u8 r4, u8 r5)
{
    (void)r3; (void)r4; (void)r5;
}
#pragma dont_inline reset

/*
 * Set a byte in either lbl_803CD7E0[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 *
 * EN v1.1 Address: 0x80281FE8, size 68b
 */
void fn_80281FE8(u8 a, u8 b, u8 v)
{
    if (b != 0xff) {
        lbl_803CD760[b][a] = v;
    } else {
        lbl_803CD7E0[a] = v;
    }
}

/*
 * Get a byte from either lbl_803CD7E0[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 *
 * EN v1.1 Address: 0x8028202C, size 68b
 */
u8 fn_8028202C(u8 a, u8 b)
{
    if (b != 0xff) {
        return lbl_803CD760[b][a];
    }
    return lbl_803CD7E0[a];
}
