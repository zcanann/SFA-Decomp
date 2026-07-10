#include "ghidra_import.h"
#include "main/audio/mcmd.h"

typedef struct InpMidiState
{
    u8 pad0[0xC0];
    u8 midiCtrl[8][16][134]; /* 0x00C0 */
    u8 fxCtrl[16][134];      /* 0x43C0 */
    u8 pad1[0x1920];         /* 0x4C20 */
    u32 globalDirty[8][16];  /* 0x6540 */
    u8 pbRange[8][16];       /* 0x6740 */
} InpMidiState;

/* Standard MIDI controller (CC) numbers handled by the RPN setter. */
#define MIDI_CC_DATA_ENTRY_MSB 6
#define MIDI_CC_DATA_ENTRY_LSB 38
#define MIDI_CC_DATA_INCREMENT 96
#define MIDI_CC_DATA_DECREMENT 97
#define MIDI_CC_RPN_LSB        100
#define MIDI_CC_RPN_MSB        101

/* RPN 0 = Pitch Bend Sensitivity (pitch bend range, in semitones). */
#define MIDI_RPN_PITCH_BEND_SENSITIVITY 0

extern u8 lbl_803CD760[];
extern u8 lbl_803BD150[];
extern McmdVoiceState* synthVoice;
extern void synthQueueVoiceInputUpdate(McmdVoiceState* voice);

static inline void inpSetRPNHi(u8 set, u8 channel, u8 value)
{
    InpMidiState* st = (InpMidiState*)lbl_803CD760;
    u16 rpn;
    u32 i;
    u8 range;

    rpn = (st->midiCtrl[set][channel][MIDI_CC_RPN_LSB]) | (st->midiCtrl[set][channel][MIDI_CC_RPN_MSB] << 8);
    switch (rpn)
    {
    case MIDI_RPN_PITCH_BEND_SENSITIVITY:
        range = value > 24 ? 24 : value;
        st->pbRange[set][channel] = range;
        for (i = 0; i < lbl_803BD150[0x210]; ++i)
        {
            if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot)
            {
                synthVoice[i].pitchBendRangeDown = range;
                synthVoice[i].pitchBendRangeUp = range;
            }
        }
        break;
    default:
        break;
    }
}

static inline void inpSetRPNLo(u8 set, u8 channel, u8 value)
{
}

static inline void inpSetRPNDec(u8 set, u8 channel)
{
    InpMidiState* st = (InpMidiState*)lbl_803CD760;
    u16 rpn;
    u32 i;
    u8 range;

    rpn = (st->midiCtrl[set][channel][MIDI_CC_RPN_LSB]) | (st->midiCtrl[set][channel][MIDI_CC_RPN_MSB] << 8);
    switch (rpn)
    {
    case MIDI_RPN_PITCH_BEND_SENSITIVITY:
        range = st->pbRange[set][channel];
        if (range != 0)
        {
            --range;
        }
        st->pbRange[set][channel] = range;
        for (i = 0; i < lbl_803BD150[0x210]; ++i)
        {
            if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot)
            {
                synthVoice[i].pitchBendRangeDown = range;
                synthVoice[i].pitchBendRangeUp = range;
            }
        }
        break;
    default:
        break;
    }
}

static inline void inpSetRPNInc(u8 set, u8 channel)
{
    InpMidiState* st = (InpMidiState*)lbl_803CD760;
    u16 rpn;
    u32 i;
    u8 range;

    rpn = (st->midiCtrl[set][channel][MIDI_CC_RPN_LSB]) | (st->midiCtrl[set][channel][MIDI_CC_RPN_MSB] << 8);
    switch (rpn)
    {
    case MIDI_RPN_PITCH_BEND_SENSITIVITY:
        range = st->pbRange[set][channel];
        if (range < 24)
        {
            ++range;
        }
        st->pbRange[set][channel] = range;
        for (i = 0; i < lbl_803BD150[0x210]; ++i)
        {
            if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot)
            {
                synthVoice[i].pitchBendRangeDown = range;
                synthVoice[i].pitchBendRangeUp = range;
            }
        }
        break;
    default:
        break;
    }
}

/*
 * inpSetMidiCtrl - combined RPN/MIDI controller setter.
 */
void inpSetMidiCtrl(u8 ctrl, u8 channel, u8 set, u8 value)
{
    InpMidiState* st = (InpMidiState*)lbl_803CD760;
    u32 i;

    if (channel == 0xFF)
    {
        return;
    }

    if (set != 0xFF)
    {
        switch (ctrl)
        {
        case MIDI_CC_DATA_ENTRY_MSB:
            inpSetRPNHi(set, channel, value);
            break;
        case MIDI_CC_DATA_ENTRY_LSB:
            inpSetRPNLo(set, channel, value);
            break;
        case MIDI_CC_DATA_INCREMENT:
            inpSetRPNDec(set, channel);
            break;
        case MIDI_CC_DATA_DECREMENT:
            inpSetRPNInc(set, channel);
            break;
        }

        st->midiCtrl[set][channel][ctrl] = value & 0x7f;
        for (i = 0; i < lbl_803BD150[0x210]; ++i)
        {
            if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot)
            {
                synthVoice[i].inputDirtyFlags = MCMD_INPUT_DIRTY_ALL;
                synthQueueVoiceInputUpdate(&synthVoice[i]);
            }
        }
        st->globalDirty[set][channel] = 0xFF;
    }
    else
    {
        switch (ctrl)
        {
        case MIDI_CC_DATA_ENTRY_MSB:
            inpSetRPNHi(set, channel, value);
            break;
        case MIDI_CC_DATA_ENTRY_LSB:
            inpSetRPNLo(set, channel, value);
            break;
        case MIDI_CC_DATA_INCREMENT:
            inpSetRPNDec(set, channel);
            break;
        case MIDI_CC_DATA_DECREMENT:
            inpSetRPNInc(set, channel);
            break;
        }

        st->fxCtrl[channel][ctrl] = value & 0x7f;
        for (i = 0; i < lbl_803BD150[0x210]; ++i)
        {
            if (set == synthVoice[i].midiEvent && channel == synthVoice[i].midiSlot)
            {
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
void inpSetMidiCtrl14(u8 ctrl, u8 channel, u8 set, u16 value)
{
    if (channel == 0xFF)
    {
        return;
    }

    if (ctrl < 64)
    {
        inpSetMidiCtrl(ctrl & 31, channel, set, value >> 7);
        inpSetMidiCtrl((ctrl & 31) + 32, channel, set, value & 0x7f);
    }
    else if (ctrl == 128 || ctrl == 129)
    {
        inpSetMidiCtrl(ctrl & 254, channel, set, value >> 7);
        inpSetMidiCtrl((ctrl & 254) + 1, channel, set, value & 0x7f);
    }
    else if (ctrl == 132 || ctrl == 133)
    {
        inpSetMidiCtrl(ctrl & 254, channel, set, value >> 7);
        inpSetMidiCtrl((ctrl & 254) + 1, channel, set, value & 0x7f);
    }
    else
    {
        inpSetMidiCtrl(ctrl, channel, set, value >> 7);
    }
}
