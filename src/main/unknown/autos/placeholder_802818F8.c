#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80279EC0.h"
#include "main/unknown/autos/placeholder_80281A9C.h"

extern u8 lbl_803CD760[];
extern u8 lbl_803BD150[];
extern u8 *synthVoice;
extern void fn_80271370(int voice);

/*
 * inpSetMidiCtrl - combined RPN/MIDI controller setter.
 *
 * EN v1.0 Address: 0x80281338
 * EN v1.0 Size: 1488b (0x5D0)
 */
void inpSetMidiCtrl(int controller, u8 slot, u8 key, u8 value)
{
    u8 *base;
    u8 *aux;
    
    int i;
    int voff;

    if (slot == INP_INVALID_SLOT) return;

    if (key != INP_INVALID_SLOT) {
        /* Per-key controller bank. */
        switch (controller) {
        case 0x6: {
            u8 *e = lbl_803CD760 + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 v = (value <= 0x18) ? value : 0x18;
                lbl_803CD760[key * INP_MIDI_SLOT_COUNT + slot + 0x6740] = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    if (key == vp[SYNTH_VOICE_MIDI_KEY_OFFSET] &&
                        slot == vp[SYNTH_VOICE_MIDI_SLOT_OFFSET]) {
                        vp[0x1d7] = v;
                        *(u8 *)(synthVoice + voff + 0x1d6) = v;
                    }
                    voff += SYNTH_VOICE_STRIDE;
                }
            }
            break;
        }
        case 0x60: {
            u8 *e = lbl_803CD760 + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 *p = lbl_803CD760 + key * INP_MIDI_SLOT_COUNT + slot + 0x6740;
                u8 v = *p;
                if (v != 0) v -= 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    if (key == vp[SYNTH_VOICE_MIDI_KEY_OFFSET] &&
                        slot == vp[SYNTH_VOICE_MIDI_SLOT_OFFSET]) {
                        vp[0x1d7] = v;
                        *(u8 *)(synthVoice + voff + 0x1d6) = v;
                    }
                    voff += SYNTH_VOICE_STRIDE;
                }
            }
            break;
        }
        case 0x61: {
            u8 *e = lbl_803CD760 + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 *p = lbl_803CD760 + key * INP_MIDI_SLOT_COUNT + slot + 0x6740;
                u8 v = *p;
                if (v < 0x18) v += 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    if (key == vp[SYNTH_VOICE_MIDI_KEY_OFFSET] &&
                        slot == vp[SYNTH_VOICE_MIDI_SLOT_OFFSET]) {
                        vp[0x1d7] = v;
                        *(u8 *)(synthVoice + voff + 0x1d6) = v;
                    }
                    voff += SYNTH_VOICE_STRIDE;
                }
            }
            break;
        }
        }
        base = lbl_803CD760 + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE + controller;
        base[0xc0] = value & 0x7f;
        voff = 0;
        for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
            u8 *vp = synthVoice + voff;
            if (key == vp[SYNTH_VOICE_MIDI_KEY_OFFSET] &&
                slot == vp[SYNTH_VOICE_MIDI_SLOT_OFFSET]) {
                *(u32 *)(vp + 0x214) = 0x1fff;
                fn_80271370((int)(synthVoice + voff));
            }
            voff += SYNTH_VOICE_STRIDE;
        }
        *(u32 *)(lbl_803CD760 + key * 0x40 + slot * 4 + 0x6540) = INP_INVALID_SLOT;
    } else {
        /* Global controller bank for this MIDI slot. */
        switch (controller) {
        case 0x6: {
            u8 *e = lbl_803CD760 + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 v = (value <= 0x18) ? value : 0x18;
                lbl_803CD760[key * INP_MIDI_SLOT_COUNT + slot + 0x6740] = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    if (key == vp[SYNTH_VOICE_MIDI_KEY_OFFSET] &&
                        slot == vp[SYNTH_VOICE_MIDI_SLOT_OFFSET]) {
                        vp[0x1d7] = v;
                        *(u8 *)(synthVoice + voff + 0x1d6) = v;
                    }
                    voff += SYNTH_VOICE_STRIDE;
                }
            }
            break;
        }
        case 0x60: {
            u8 *e = lbl_803CD760 + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 *p = lbl_803CD760 + key * INP_MIDI_SLOT_COUNT + slot + 0x6740;
                u8 v = *p;
                if (v != 0) v -= 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    if (key == vp[SYNTH_VOICE_MIDI_KEY_OFFSET] &&
                        slot == vp[SYNTH_VOICE_MIDI_SLOT_OFFSET]) {
                        vp[0x1d7] = v;
                        *(u8 *)(synthVoice + voff + 0x1d6) = v;
                    }
                    voff += SYNTH_VOICE_STRIDE;
                }
            }
            break;
        }
        case 0x61: {
            u8 *e = lbl_803CD760 + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 *p = lbl_803CD760 + key * INP_MIDI_SLOT_COUNT + slot + 0x6740;
                u8 v = *p;
                if (v < 0x18) v += 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    if (key == vp[SYNTH_VOICE_MIDI_KEY_OFFSET] &&
                        slot == vp[SYNTH_VOICE_MIDI_SLOT_OFFSET]) {
                        vp[0x1d7] = v;
                        *(u8 *)(synthVoice + voff + 0x1d6) = v;
                    }
                    voff += SYNTH_VOICE_STRIDE;
                }
            }
            break;
        }
        }
        aux = lbl_803CD760 + slot * INP_MIDI_CTRL_BANK_SIZE + controller;
        aux[0x43c0] = value & 0x7f;
        voff = 0;
        for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
            u8 *vp = synthVoice + voff;
            if (key == vp[SYNTH_VOICE_MIDI_KEY_OFFSET] &&
                slot == vp[SYNTH_VOICE_MIDI_SLOT_OFFSET]) {
                *(u32 *)(vp + 0x214) = 0x1fff;
                fn_80271370((int)(synthVoice + voff));
            }
            voff += SYNTH_VOICE_STRIDE;
        }
    }
}

/*
 * inpSetMidiCtrl14 - wrapper that splits a 16-bit data word into two
 * 7-bit MIDI controller bytes and dispatches to the MIDI-control setter.
 */
void inpSetMidiCtrl14(u8 controller, u8 slot, u8 key, u32 data)
{
    if (slot != INP_INVALID_SLOT) {
        if (controller < 0x40) {
            inpSetMidiCtrl(controller & 0x1f, slot, key, (data >> 7) & 0xff);
            inpSetMidiCtrl((controller & 0x1f) + 0x20, slot, key, data & 0x7f);
        } else if (((controller - 0x80) & 0xff) < 2) {
            inpSetMidiCtrl(controller & 0xfe, slot, key, (data >> 7) & 0xff);
            inpSetMidiCtrl((controller & 0xfe) + 1, slot, key, data & 0x7f);
        } else if (((controller - 0x84) & 0xff) < 2) {
            inpSetMidiCtrl(controller & 0xfe, slot, key, (data >> 7) & 0xff);
            inpSetMidiCtrl((controller & 0xfe) + 1, slot, key, data & 0x7f);
        } else {
            inpSetMidiCtrl(controller, slot, key, (data >> 7) & 0xff);
        }
    }
}
