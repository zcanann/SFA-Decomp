#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80281A9C.h"

extern void *memcpy(void *dst, const void *src, u32 n);
extern void inpSetMidiLastNote(u8 a, u8 b, u8 v);
extern int inpTranslateExCtrl(int input);

extern u8 sInpMidiCtrlFullResetPreset[];
extern u8 sInpMidiCtrlMaskedResetPreset[];
extern u8 lbl_803CD760[][INP_MIDI_SLOT_COUNT];
extern u8 gInpMidiLastNote[];
extern u8 gInpMidiCtrlByKey[];
extern u8 gInpMidiCtrl[];
extern u8 gInpChannelDefaultsByKey[][INP_MIDI_SLOT_COUNT];
extern u8 gInpChannelDefaults[];

/*
 * Reset a MIDI-controller/default table from one of two preset banks,
 * then mark the last-note/controller slot dirty via inpSetMidiLastNote.
 *
 * EN v1.1 Address: 0x80281A30, size 244b
 */
void inpResetMidiCtrl(u8 a, u8 b, u32 mode)
{
    u8 *src;
    u8 *dst;

    if (mode != 0) {
        src = sInpMidiCtrlFullResetPreset;
    } else {
        src = sInpMidiCtrlMaskedResetPreset;
    }

    if (b != INP_INVALID_SLOT) {
        dst = gInpMidiCtrlByKey + b * INP_MIDI_KEY_STRIDE + a * INP_MIDI_CTRL_BANK_SIZE;
    } else {
        dst = gInpMidiCtrl + a * INP_MIDI_CTRL_BANK_SIZE;
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

    inpSetMidiLastNote(a, b, 0xff);
}

/*
 * Read a 14-bit MIDI controller value from either the global channel defaults
 * or the per-key controller bank.
 */
u32 inpGetMidiCtrl(u8 controller, u32 slot, u32 key)
{
    u32 ctrl;
    u8 *base;

    slot &= 0xff;
    if (slot == INP_INVALID_SLOT) {
        return 0;
    }

    key &= 0xff;
    ctrl = controller & 0xff;
    if (key == INP_INVALID_SLOT) {
        base = gInpMidiCtrl + slot * INP_MIDI_CTRL_BANK_SIZE;
        if (ctrl < 0x40) {
            return ((u32)base[controller & 0x1f] << 7) |
                   (u32)base[(controller & 0x1f) + 0x20];
        }
        if (ctrl < 0x46) {
            if (base[ctrl] < 0x40) {
                return 0;
            }
            return 0x3fff;
        }
        if (ctrl > 0x5f && ctrl < 0x66) {
            return 0;
        }
        if (((controller - 0x80) & 0xff) < 2) {
            return ((u32)base[controller & 0xfe] << 7) | (u32)base[(controller & 0xfe) + 1];
        }
        if (((controller - 0x84) & 0xff) < 2) {
            return ((u32)base[controller & 0xfe] << 7) | (u32)base[(controller & 0xfe) + 1];
        }
        return (u32)base[ctrl] << 7;
    }

    base = gInpMidiCtrlByKey + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE;
    if (ctrl < 0x40) {
        return ((u32)base[controller & 0x1f] << 7) |
               (u32)base[(controller & 0x1f) + 0x20];
    }
    if (ctrl < 0x46) {
        if (base[ctrl] < 0x40) {
            return 0;
        }
        return 0x3fff;
    }
    if (ctrl > 0x5f && ctrl < 0x66) {
        return 0;
    }
    if (((controller - 0x80) & 0xff) < 2) {
        return ((u32)base[controller & 0xfe] << 7) | (u32)base[(controller & 0xfe) + 1];
    }
    if (((controller - 0x84) & 0xff) < 2) {
        return ((u32)base[controller & 0xfe] << 7) | (u32)base[(controller & 0xfe) + 1];
    }
    return (u32)base[ctrl] << 7;
}

/*
 * Returns pointer into either 1D or 2D voice-state table.
 *
 * EN v1.1 Address: 0x80281DB0, size 60b
 */
u8 *inpGetChannelDefaults(u8 a, u8 b)
{
    if (b == INP_INVALID_SLOT) {
        return &gInpChannelDefaults[a];
    }
    return &gInpChannelDefaultsByKey[b][a];
}

/*
 * Stores 2 into voice-state slot (1D or 2D variant).
 *
 * EN v1.1 Address: 0x80281DEC, size 68b
 */
void inpResetChannelDefaults(u8 a, u8 b)
{
    u8 *p;
    if (b != INP_INVALID_SLOT) {
        p = &gInpChannelDefaultsByKey[b][a];
    } else {
        p = &gInpChannelDefaults[a];
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
void inpAddCtrl(int obj, int b, int c, int d, u32 flag)
{
    u8 counter;
    if ((d & 0xff) == 0) {
        *(u8 *)(obj + 0x22) = 0;
    }
    counter = *(u8 *)(obj + 0x22);
    if (counter < 4) {
        *(u8 *)(obj + 0x22) = counter + 1;
        if (flag == 0) {
            b = inpTranslateExCtrl(b);
        } else {
            d |= 0x10;
        }
        *(u8 *)(obj + counter * 8) = (u8)b;
        *(u8 *)(obj + counter * 8 + 1) = (u8)d;
        *(int *)(obj + counter * 8 + 4) = c;
    }
}

/*
 * Copy one FX controller value between two voice slots' global controller banks.
 */
void inpFXCopyCtrl(u8 controller, int dstState, int srcState)
{
    u32 ctrl;
    u32 dstVoice;
    u32 srcVoice;
    u8 *dst;
    u8 *src;

    ctrl = controller & 0xff;
    dstVoice = *(u32 *)(dstState + 0xf4) & 0xff;
    srcVoice = *(u32 *)(srcState + 0xf4) & 0xff;
    dst = gInpMidiCtrl + dstVoice * INP_MIDI_CTRL_BANK_SIZE;
    src = gInpMidiCtrl + srcVoice * INP_MIDI_CTRL_BANK_SIZE;

    if (ctrl < 0x40) {
        ctrl = controller & 0x1f;
        dst[ctrl] = src[ctrl];
        dst[ctrl + 0x20] = src[ctrl + 0x20];
        return;
    }
    if (((controller - 0x80) & 0xff) < 2) {
        ctrl = controller & 0xfe;
        dst[ctrl] = src[ctrl];
        dst[ctrl + 1] = src[ctrl + 1];
        return;
    }
    if (((controller - 0x84) & 0xff) < 2) {
        ctrl = controller & 0xfe;
        dst[ctrl] = src[ctrl];
        dst[ctrl + 1] = src[ctrl + 1];
        return;
    }
    dst[ctrl] = src[ctrl];
}

/*
 * Set a byte in either gInpMidiLastNote[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 *
 * EN v1.1 Address: 0x80281FE8, size 68b
 */
void inpSetMidiLastNote(u8 a, u8 b, u8 v)
{
    if (b != INP_INVALID_SLOT) {
        lbl_803CD760[b][a] = v;
    } else {
        gInpMidiLastNote[a] = v;
    }
}

/*
 * Get a byte from either gInpMidiLastNote[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 *
 * EN v1.1 Address: 0x8028202C, size 68b
 */
u8 inpGetMidiLastNote(u8 a, u8 b)
{
    if (b != INP_INVALID_SLOT) {
        return lbl_803CD760[b][a];
    }
    return gInpMidiLastNote[a];
}
