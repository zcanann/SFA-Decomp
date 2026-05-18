#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/unknown/autos/placeholder_80279EC0.h"
#include "main/unknown/autos/placeholder_80281A9C.h"

extern u8 lbl_803CD760[];
extern u8 lbl_803BD150[];
extern u8 *synthVoice;
extern void synthQueueVoiceInputUpdate(int voice);

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
                lbl_803CD760[key * INP_MIDI_SLOT_COUNT + slot +
                              INP_MIDI_CHANNEL_DEFAULTS_BY_KEY_OFFSET] = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    McmdVoiceState *voice = (McmdVoiceState *)vp;
                    if (key == voice->midiEvent && slot == voice->midiSlot) {
                        voice->pitchBendRangeDown = v;
                        voice->pitchBendRangeUp = v;
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
                u8 *p = lbl_803CD760 + key * INP_MIDI_SLOT_COUNT + slot +
                        INP_MIDI_CHANNEL_DEFAULTS_BY_KEY_OFFSET;
                u8 v = *p;
                if (v != 0) v -= 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    McmdVoiceState *voice = (McmdVoiceState *)vp;
                    if (key == voice->midiEvent && slot == voice->midiSlot) {
                        voice->pitchBendRangeDown = v;
                        voice->pitchBendRangeUp = v;
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
                u8 *p = lbl_803CD760 + key * INP_MIDI_SLOT_COUNT + slot +
                        INP_MIDI_CHANNEL_DEFAULTS_BY_KEY_OFFSET;
                u8 v = *p;
                if (v < 0x18) v += 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    McmdVoiceState *voice = (McmdVoiceState *)vp;
                    if (key == voice->midiEvent && slot == voice->midiSlot) {
                        voice->pitchBendRangeDown = v;
                        voice->pitchBendRangeUp = v;
                    }
                    voff += SYNTH_VOICE_STRIDE;
                }
            }
            break;
        }
        }
        base = lbl_803CD760 + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE + controller;
        base[INP_MIDI_CTRL_BY_KEY_OFFSET] = value & 0x7f;
        voff = 0;
        for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
            u8 *vp = synthVoice + voff;
            McmdVoiceState *voice = (McmdVoiceState *)vp;
            if (key == voice->midiEvent && slot == voice->midiSlot) {
                voice->inputDirtyFlags = MCMD_INPUT_DIRTY_ALL;
                synthQueueVoiceInputUpdate((int)voice);
            }
            voff += SYNTH_VOICE_STRIDE;
        }
        *(u32 *)(lbl_803CD760 + key * INP_MIDI_AUX_KEY_STRIDE + slot * 4 +
                 INP_MIDI_AUX_BY_KEY_OFFSET) = INP_INVALID_SLOT;
    } else {
        /* Global controller bank for this MIDI slot. */
        switch (controller) {
        case 0x6: {
            u8 *e = lbl_803CD760 + key * INP_MIDI_KEY_STRIDE + slot * INP_MIDI_CTRL_BANK_SIZE;
            u16 hi = ((u16)e[0x125] << 8) | e[0x124];
            if ((hi & 0xffff) != 0) break;
            {
                u8 v = (value <= 0x18) ? value : 0x18;
                lbl_803CD760[key * INP_MIDI_SLOT_COUNT + slot +
                              INP_MIDI_CHANNEL_DEFAULTS_BY_KEY_OFFSET] = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    McmdVoiceState *voice = (McmdVoiceState *)vp;
                    if (key == voice->midiEvent && slot == voice->midiSlot) {
                        voice->pitchBendRangeDown = v;
                        voice->pitchBendRangeUp = v;
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
                u8 *p = lbl_803CD760 + key * INP_MIDI_SLOT_COUNT + slot +
                        INP_MIDI_CHANNEL_DEFAULTS_BY_KEY_OFFSET;
                u8 v = *p;
                if (v != 0) v -= 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    McmdVoiceState *voice = (McmdVoiceState *)vp;
                    if (key == voice->midiEvent && slot == voice->midiSlot) {
                        voice->pitchBendRangeDown = v;
                        voice->pitchBendRangeUp = v;
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
                u8 *p = lbl_803CD760 + key * INP_MIDI_SLOT_COUNT + slot +
                        INP_MIDI_CHANNEL_DEFAULTS_BY_KEY_OFFSET;
                u8 v = *p;
                if (v < 0x18) v += 1;
                *p = v;
                voff = 0;
                for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
                    u8 *vp = synthVoice + voff;
                    McmdVoiceState *voice = (McmdVoiceState *)vp;
                    if (key == voice->midiEvent && slot == voice->midiSlot) {
                        voice->pitchBendRangeDown = v;
                        voice->pitchBendRangeUp = v;
                    }
                    voff += SYNTH_VOICE_STRIDE;
                }
            }
            break;
        }
        }
        aux = lbl_803CD760 + slot * INP_MIDI_CTRL_BANK_SIZE + controller;
        aux[INP_MIDI_CTRL_GLOBAL_OFFSET] = value & 0x7f;
        voff = 0;
        for (i = 0; (u32)i < (u32)lbl_803BD150[0x210]; i++) {
            u8 *vp = synthVoice + voff;
            McmdVoiceState *voice = (McmdVoiceState *)vp;
            if (key == voice->midiEvent && slot == voice->midiSlot) {
                voice->inputDirtyFlags = MCMD_INPUT_DIRTY_ALL;
                synthQueueVoiceInputUpdate((int)voice);
            }
            voff += SYNTH_VOICE_STRIDE;
        }
    }
}

/*
 * inpSetMidiCtrl14 - wrapper that splits a 16-bit data word into two
 * 7-bit MIDI controller bytes and dispatches to the MIDI-control setter.
 */
void inpSetMidiCtrl14(int controller, u8 slot, u8 key, u16 data)
{
    u8 ctrl;

    if (slot == INP_INVALID_SLOT) {
        return;
    }

    ctrl = controller;
    if (ctrl < 0x40) {
        u32 base = ctrl & 0x1f;
        inpSetMidiCtrl(base, slot, key, (data >> 7) & 0xff);
        inpSetMidiCtrl(base + 0x20, slot, key, data & 0x7f);
        return;
    }
    if ((u8)(controller - 0x80) <= 1U) {
        u32 base = ctrl & 0xfe;
        inpSetMidiCtrl(base, slot, key, (data >> 7) & 0xff);
        inpSetMidiCtrl(base + 1, slot, key, data & 0x7f);
        return;
    }
    if ((u8)(controller - 0x84) <= 1U) {
        u32 base = ctrl & 0xfe;
        inpSetMidiCtrl(base, slot, key, (data >> 7) & 0xff);
        inpSetMidiCtrl(base + 1, slot, key, data & 0x7f);
        return;
    }
    inpSetMidiCtrl(controller, slot, key, (data >> 7) & 0xff);
}
