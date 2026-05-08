#include "ghidra_import.h"

extern u8 lbl_803CD760[];
extern u8 lbl_803BD150[];
extern u8 *lbl_803DE268;
extern void fn_80271370(int voice);

/*
 * inpSetMidiCtrl - combined RPN/MIDI controller setter.
 *
 * EN v1.0 Address: 0x80281338
 * EN v1.0 Size: 1488b (0x5D0)
 */
void inpSetMidiCtrl(int idx, u8 a, u8 b, u8 mask)
{
    u8 *base;
    u8 *aux;
    
    int i;
    int voff;

    if (a == 0xff) return;

    if (b != 0xff) {
        /* main branch - b is concrete */
        switch (idx) {
        case 0x6: {
            u8 *e = lbl_803CD760 + b * 0x860 + a * 0x86;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 v = (mask <= 0x18) ? mask : 0x18;
                lbl_803CD760[b * 0x10 + a + 0x6740] = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = lbl_803DE268 + voff;
                    if (b == vp[0x122] && a == vp[0x121]) {
                        vp[0x1d7] = v;
                        *(u8 *)(lbl_803DE268 + voff + 0x1d6) = v;
                    }
                    voff += 0x404;
                }
            }
            break;
        }
        case 0x60: {
            u8 *e = lbl_803CD760 + b * 0x860 + a * 0x86;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 *p = lbl_803CD760 + b * 0x10 + a + 0x6740;
                u8 v = *p;
                if (v != 0) v -= 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = lbl_803DE268 + voff;
                    if (b == vp[0x122] && a == vp[0x121]) {
                        vp[0x1d7] = v;
                        *(u8 *)(lbl_803DE268 + voff + 0x1d6) = v;
                    }
                    voff += 0x404;
                }
            }
            break;
        }
        case 0x61: {
            u8 *e = lbl_803CD760 + b * 0x860 + a * 0x86;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 *p = lbl_803CD760 + b * 0x10 + a + 0x6740;
                u8 v = *p;
                if (v < 0x18) v += 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = lbl_803DE268 + voff;
                    if (b == vp[0x122] && a == vp[0x121]) {
                        vp[0x1d7] = v;
                        *(u8 *)(lbl_803DE268 + voff + 0x1d6) = v;
                    }
                    voff += 0x404;
                }
            }
            break;
        }
        }
        base = lbl_803CD760 + b * 0x860 + a * 0x86 + idx;
        base[0xc0] = mask & 0x7f;
        voff = 0;
        for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
            u8 *vp = lbl_803DE268 + voff;
            if (b == vp[0x122] && a == vp[0x121]) {
                *(u32 *)(vp + 0x214) = 0x1fff;
                fn_80271370((int)(lbl_803DE268 + voff));
            }
            voff += 0x404;
        }
        *(u32 *)(lbl_803CD760 + b * 0x40 + a * 4 + 0x6540) = 0xff;
    } else {
        /* b == 0xff branch - same dispatch but different common path */
        switch (idx) {
        case 0x6: {
            u8 *e = lbl_803CD760 + b * 0x860 + a * 0x86;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 v = (mask <= 0x18) ? mask : 0x18;
                lbl_803CD760[b * 0x10 + a + 0x6740] = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = lbl_803DE268 + voff;
                    if (b == vp[0x122] && a == vp[0x121]) {
                        vp[0x1d7] = v;
                        *(u8 *)(lbl_803DE268 + voff + 0x1d6) = v;
                    }
                    voff += 0x404;
                }
            }
            break;
        }
        case 0x60: {
            u8 *e = lbl_803CD760 + b * 0x860 + a * 0x86;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 *p = lbl_803CD760 + b * 0x10 + a + 0x6740;
                u8 v = *p;
                if (v != 0) v -= 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = lbl_803DE268 + voff;
                    if (b == vp[0x122] && a == vp[0x121]) {
                        vp[0x1d7] = v;
                        *(u8 *)(lbl_803DE268 + voff + 0x1d6) = v;
                    }
                    voff += 0x404;
                }
            }
            break;
        }
        case 0x61: {
            u8 *e = lbl_803CD760 + b * 0x860 + a * 0x86;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 *p = lbl_803CD760 + b * 0x10 + a + 0x6740;
                u8 v = *p;
                if (v < 0x18) v += 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = lbl_803DE268 + voff;
                    if (b == vp[0x122] && a == vp[0x121]) {
                        vp[0x1d7] = v;
                        *(u8 *)(lbl_803DE268 + voff + 0x1d6) = v;
                    }
                    voff += 0x404;
                }
            }
            break;
        }
        }
        aux = lbl_803CD760 + a * 0x86 + idx;
        aux[0x43c0] = mask & 0x7f;
        voff = 0;
        for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
            u8 *vp = lbl_803DE268 + voff;
            if (b == vp[0x122] && a == vp[0x121]) {
                *(u32 *)(vp + 0x214) = 0x1fff;
                fn_80271370((int)(lbl_803DE268 + voff));
            }
            voff += 0x404;
        }
    }
}

/*
 * inpSetMidiCtrl14 - wrapper that splits a 16-bit data word into two
 * 7-bit MIDI controller bytes and dispatches to the MIDI-control setter.
 */
void inpSetMidiCtrl14(u8 idx, u8 a, u8 b, u32 data)
{
    if (a != 0xff) {
        if (idx < 0x40) {
            inpSetMidiCtrl(idx & 0x1f, a, b, (data >> 7) & 0xff);
            inpSetMidiCtrl((idx & 0x1f) + 0x20, a, b, data & 0x7f);
        } else if (((idx - 0x80) & 0xff) < 2) {
            inpSetMidiCtrl(idx & 0xfe, a, b, (data >> 7) & 0xff);
            inpSetMidiCtrl((idx & 0xfe) + 1, a, b, data & 0x7f);
        } else if (((idx - 0x84) & 0xff) < 2) {
            inpSetMidiCtrl(idx & 0xfe, a, b, (data >> 7) & 0xff);
            inpSetMidiCtrl((idx & 0xfe) + 1, a, b, data & 0x7f);
        } else {
            inpSetMidiCtrl(idx, a, b, (data >> 7) & 0xff);
        }
    }
}
