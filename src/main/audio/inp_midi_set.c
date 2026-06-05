#include "ghidra_import.h"
#include "main/audio/mcmd.h"

typedef struct InpMidiState {
    u8 pad0[0xC0];
    u8 midiCtrl[8][16][134];  /* 0x00C0 */
    u8 fxCtrl[16][134];       /* 0x43C0 */
    u8 pad1[0x1920];          /* 0x4C20 */
    u32 globalDirty[8][16];   /* 0x6540 */
    u8 pbRange[8][16];        /* 0x6740 */
} InpMidiState;

extern u8 lbl_803CD760[];
extern u8 lbl_803BD150[];
extern McmdVoiceState *synthVoice;
extern void synthQueueVoiceInputUpdate(McmdVoiceState *voice);

/*
 * inpSetMidiCtrl - combined RPN/MIDI controller setter.
 *
 * EN v1.0 Address: 0x80281338
 * EN v1.0 Size: 1488b (0x5D0)
 */
void inpSetMidiCtrl(u8 ctrl, u8 channel, u8 set, u8 value)
{
    InpMidiState *st = (InpMidiState *)lbl_803CD760;
    u32 i;
    u16 rpn;
    u8 range;

    if (channel == 0xFF) {
        return;
    }

    if (set != 0xFF) {
        switch (ctrl) {
        case 6:
            rpn = (st->midiCtrl[set][channel][100]) | (st->midiCtrl[set][channel][101] << 8);
            switch (rpn) {
            case 0:
                range = value > 24 ? 24 : value;
                st->pbRange[set][channel] = range;
                for (i = 0; i < lbl_803BD150[0x210]; i++) {
                    if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot) {
                        synthVoice[i].pitchBendRangeDown = range;
                        synthVoice[i].pitchBendRangeUp = range;
                    }
                }
                break;
            }
            break;
        case 38:
            break;
        case 96:
            rpn = (st->midiCtrl[set][channel][100]) | (st->midiCtrl[set][channel][101] << 8);
            switch (rpn) {
            case 0:
                range = st->pbRange[set][channel];
                if (range != 0) {
                    --range;
                }
                st->pbRange[set][channel] = range;
                for (i = 0; i < lbl_803BD150[0x210]; i++) {
                    if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot) {
                        synthVoice[i].pitchBendRangeDown = range;
                        synthVoice[i].pitchBendRangeUp = range;
                    }
                }
                break;
            }
            break;
        case 97:
            rpn = (st->midiCtrl[set][channel][100]) | (st->midiCtrl[set][channel][101] << 8);
            switch (rpn) {
            case 0:
                range = st->pbRange[set][channel];
                if (range < 24) {
                    ++range;
                }
                st->pbRange[set][channel] = range;
                for (i = 0; i < lbl_803BD150[0x210]; i++) {
                    if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot) {
                        synthVoice[i].pitchBendRangeDown = range;
                        synthVoice[i].pitchBendRangeUp = range;
                    }
                }
                break;
            }
            break;
        }

        st->midiCtrl[set][channel][ctrl] = value & 0x7f;
        for (i = 0; i < lbl_803BD150[0x210]; i++) {
            if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot) {
                synthVoice[i].inputDirtyFlags = MCMD_INPUT_DIRTY_ALL;
                synthQueueVoiceInputUpdate(&synthVoice[i]);
            }
        }
        st->globalDirty[set][channel] = 0xFF;
    } else {
        switch (ctrl) {
        case 6:
            rpn = (st->midiCtrl[set][channel][100]) | (st->midiCtrl[set][channel][101] << 8);
            switch (rpn) {
            case 0:
                range = value > 24 ? 24 : value;
                st->pbRange[set][channel] = range;
                for (i = 0; i < lbl_803BD150[0x210]; i++) {
                    if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot) {
                        synthVoice[i].pitchBendRangeDown = range;
                        synthVoice[i].pitchBendRangeUp = range;
                    }
                }
                break;
            }
            break;
        case 38:
            break;
        case 96:
            rpn = (st->midiCtrl[set][channel][100]) | (st->midiCtrl[set][channel][101] << 8);
            switch (rpn) {
            case 0:
                range = st->pbRange[set][channel];
                if (range != 0) {
                    --range;
                }
                st->pbRange[set][channel] = range;
                for (i = 0; i < lbl_803BD150[0x210]; i++) {
                    if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot) {
                        synthVoice[i].pitchBendRangeDown = range;
                        synthVoice[i].pitchBendRangeUp = range;
                    }
                }
                break;
            }
            break;
        case 97:
            rpn = (st->midiCtrl[set][channel][100]) | (st->midiCtrl[set][channel][101] << 8);
            switch (rpn) {
            case 0:
                range = st->pbRange[set][channel];
                if (range < 24) {
                    ++range;
                }
                st->pbRange[set][channel] = range;
                for (i = 0; i < lbl_803BD150[0x210]; i++) {
                    if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot) {
                        synthVoice[i].pitchBendRangeDown = range;
                        synthVoice[i].pitchBendRangeUp = range;
                    }
                }
                break;
            }
            break;
        }

        st->fxCtrl[channel][ctrl] = value & 0x7f;
        for (i = 0; i < lbl_803BD150[0x210]; i++) {
            if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot) {
                synthVoice[i].inputDirtyFlags = MCMD_INPUT_DIRTY_ALL;
                synthQueueVoiceInputUpdate(&synthVoice[i]);
            }
        }
    }
}

/*
 * inpSetMidiCtrl14 - wrapper that splits a 16-bit data word into two
 * 7-bit MIDI controller bytes and dispatches to the MIDI-control setter.
 */
void inpSetMidiCtrl14(u8 ctrl, u8 channel, u8 set, u16 data)
{
    if (channel == 0xFF) {
        return;
    }

    if (ctrl < 64) {
        u32 base = ctrl & 31;
        inpSetMidiCtrl(base, channel, set, (data >> 7) & 0xff);
        inpSetMidiCtrl(base + 32, channel, set, data & 0x7f);
        return;
    }
    if (ctrl == 128 || ctrl == 129) {
        inpSetMidiCtrl(ctrl & 254, channel, set, (data >> 7) & 0xff);
        inpSetMidiCtrl((ctrl & 254) + 1, channel, set, data & 0x7f);
        return;
    }
    if (ctrl == 132 || ctrl == 133) {
        inpSetMidiCtrl(ctrl & 254, channel, set, (data >> 7) & 0xff);
        inpSetMidiCtrl((ctrl & 254) + 1, channel, set, data & 0x7f);
        return;
    }
    inpSetMidiCtrl(ctrl, channel, set, (data >> 7) & 0xff);
}
