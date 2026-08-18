#include "musyx/inp_midi.h"
#include "musyx/mcmd.h"
#include "musyx/mcmd_exec.h"
#include "musyx/synth_config.h"
#include "musyx/synth_voice.h"
#include "string.h"
#include "musyx/inp_ctrl.h"
#include "musyx/snd_core.h"


/* Standard MIDI controller (CC) numbers handled by the RPN setter. */
#define MIDI_CC_DATA_ENTRY_MSB 6
#define MIDI_CC_DATA_ENTRY_LSB 38
#define MIDI_CC_DATA_INCREMENT 96
#define MIDI_CC_DATA_DECREMENT 97
#define MIDI_CC_RPN_LSB        100
#define MIDI_CC_RPN_MSB        101

/* RPN 0 = Pitch Bend Sensitivity (pitch bend range, in semitones). */
#define MIDI_RPN_PITCH_BEND_SENSITIVITY 0

static u8 lbl_803CD760[8][INP_MIDI_SLOT_COUNT];
static u8 gInpMidiLastNote[64];
static u8 gInpMidiCtrlByKey[8][INP_MIDI_SLOT_COUNT][INP_MIDI_CTRL_BANK_SIZE];
static u8 gInpMidiCtrl[64][INP_MIDI_CTRL_BANK_SIZE];
static u32 lbl_803D3CA0[8][INP_MIDI_SLOT_COUNT];
static u8 gInpChannelDefaultsByKey[8][INP_MIDI_SLOT_COUNT];
static u8 gInpChannelDefaults[64];


static inline void inpSetRPNHi(u8 set, u8 channel, u8 value)
{
    InpMidiState* st = (InpMidiState*)lbl_803CD760;
    u16 rpn;
    u32 i;
    u8 range;

    rpn = gInpMidiCtrlByKey[set][channel][MIDI_CC_RPN_LSB] |
          (gInpMidiCtrlByKey[set][channel][MIDI_CC_RPN_MSB] << 8);
    switch (rpn)
    {
    case MIDI_RPN_PITCH_BEND_SENSITIVITY:
        range = value > 24 ? 24 : value;
        st->pbRange[set][channel] = range;
        for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; ++i)
        {
            if (set == synthVoice[i].midiSet && channel == synthVoice[i].midi)
            {
                synthVoice[i].pbUpperKeyRange = range;
                synthVoice[i].pbLowerKeyRange = range;
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

    rpn = gInpMidiCtrlByKey[set][channel][MIDI_CC_RPN_LSB] |
          (gInpMidiCtrlByKey[set][channel][MIDI_CC_RPN_MSB] << 8);
    switch (rpn)
    {
    case MIDI_RPN_PITCH_BEND_SENSITIVITY:
        range = st->pbRange[set][channel];
        if (range != 0)
        {
            --range;
        }
        st->pbRange[set][channel] = range;
        for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; ++i)
        {
            if (set == synthVoice[i].midiSet && channel == synthVoice[i].midi)
            {
                synthVoice[i].pbUpperKeyRange = range;
                synthVoice[i].pbLowerKeyRange = range;
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

    rpn = gInpMidiCtrlByKey[set][channel][MIDI_CC_RPN_LSB] |
          (gInpMidiCtrlByKey[set][channel][MIDI_CC_RPN_MSB] << 8);
    switch (rpn)
    {
    case MIDI_RPN_PITCH_BEND_SENSITIVITY:
        range = st->pbRange[set][channel];
        if (range < 24)
        {
            ++range;
        }
        st->pbRange[set][channel] = range;
        for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; ++i)
        {
            if (set == synthVoice[i].midiSet && channel == synthVoice[i].midi)
            {
                synthVoice[i].pbUpperKeyRange = range;
                synthVoice[i].pbLowerKeyRange = range;
            }
        }
        break;
    default:
        break;
    }
}

void inpSetGlobalMIDIDirtyFlag(u8 channel, u8 set, u32 flags)
{
    lbl_803D3CA0[set][channel] |= flags;
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

        gInpMidiCtrlByKey[set][channel][ctrl] = value & 0x7f;
        for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; ++i)
        {
            if (set == synthVoice[i].midiSet && channel == synthVoice[i].midi)
            {
                synthVoice[i].midiDirtyFlags = MCMD_INPUT_DIRTY_ALL;
                synthKeyStateUpdate(&synthVoice[i]);
            }
        }
        lbl_803D3CA0[set][channel] = 0xFF;
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
        for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; ++i)
        {
            if (set == synthVoice[i].midiSet && channel == synthVoice[i].midi)
            {
                synthVoice[i].midiDirtyFlags = MCMD_INPUT_DIRTY_ALL;
                synthKeyStateUpdate(&synthVoice[i]);
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
    else if (ctrl == MCMD_CTRL_PITCH_BEND || ctrl == MCMD_CTRL_PITCH_BEND + 1)
    {
        inpSetMidiCtrl(ctrl & 254, channel, set, value >> 7);
        inpSetMidiCtrl((ctrl & 254) + 1, channel, set, value & 0x7f);
    }
    else if (ctrl == MCMD_CTRL_DOPPLER || ctrl == MCMD_CTRL_DOPPLER + 1)
    {
        inpSetMidiCtrl(ctrl & 254, channel, set, value >> 7);
        inpSetMidiCtrl((ctrl & 254) + 1, channel, set, value & 0x7f);
    }
    else
    {
        inpSetMidiCtrl(ctrl, channel, set, value >> 7);
    }
}

extern u8 sInpMidiCtrlFullResetPreset[];
extern u8 sInpMidiCtrlMaskedResetPreset[];

/*
 * Reset a MIDI-controller/default table from one of two preset banks,
 * then mark the last-note/controller slot dirty via inpSetMidiLastNote.
 */
void inpResetMidiCtrl(u8 channel, u8 key, u32 mode)
{
    u8* dst;
    u8* src;

    src = (mode != 0) ? sInpMidiCtrlFullResetPreset : sInpMidiCtrlMaskedResetPreset;

    if (key != INP_INVALID_SLOT)
    {
        dst = gInpMidiCtrlByKey[key][channel];
    }
    else
    {
        dst = gInpMidiCtrl[channel];
    }

    if (mode != 0)
    {
        memcpy(dst, src, 0x86);
    }
    else
    {
        int i;
        for (i = 0; i < 0x86; i++)
        {
            if (src[i] != 0xff)
            {
                dst[i] = src[i];
            }
        }
    }

    inpSetMidiLastNote(channel, key, 0xff);
}

/*
 * Read a 14-bit MIDI controller value from either the global channel defaults
 * or the per-key controller bank.
 */
u16 inpGetMidiCtrl(u8 controller, u8 slot, u8 key)
{
    if (slot != INP_INVALID_SLOT)
    {
        if (key != INP_INVALID_SLOT)
        {
            if (controller < 0x40)
            {
                return gInpMidiCtrlByKey[key][slot][controller & 0x1f] << 7 |
                       gInpMidiCtrlByKey[key][slot][(controller & 0x1f) + 0x20];
            }
            if (controller < 0x46)
            {
                return (gInpMidiCtrlByKey[key][slot][controller] < 0x40) ? 0 : 0x3fff;
            }
            if (controller >= 0x60 && controller < 0x66)
            {
                return 0;
            }
            if (controller == MCMD_CTRL_PITCH_BEND || controller == MCMD_CTRL_PITCH_BEND + 1)
            {
                return (gInpMidiCtrlByKey[key][slot][controller & 0xfe] << 7) |
                       gInpMidiCtrlByKey[key][slot][(controller & 0xfe) + 1];
            }
            if (controller == MCMD_CTRL_DOPPLER || controller == MCMD_CTRL_DOPPLER + 1)
            {
                return (gInpMidiCtrlByKey[key][slot][controller & 0xfe] << 7) |
                       gInpMidiCtrlByKey[key][slot][(controller & 0xfe) + 1];
            }
            return gInpMidiCtrlByKey[key][slot][controller] << 7;
        }

        if (controller < 0x40)
        {
            return (gInpMidiCtrl[slot][controller & 0x1f] << 7) |
                   gInpMidiCtrl[slot][(controller & 0x1f) + 0x20];
        }
        if (controller < 0x46)
        {
            return (gInpMidiCtrl[slot][controller] < 0x40) ? 0 : 0x3fff;
        }
        if (controller >= 0x60 && controller < 0x66)
        {
            return 0;
        }
        if (controller == MCMD_CTRL_PITCH_BEND || controller == MCMD_CTRL_PITCH_BEND + 1)
        {
            return (gInpMidiCtrl[slot][controller & 0xfe] << 7) |
                   gInpMidiCtrl[slot][(controller & 0xfe) + 1];
        }
        if (controller == MCMD_CTRL_DOPPLER || controller == MCMD_CTRL_DOPPLER + 1)
        {
            return (gInpMidiCtrl[slot][controller & 0xfe] << 7) |
                   gInpMidiCtrl[slot][(controller & 0xfe) + 1];
        }
        return gInpMidiCtrl[slot][controller] << 7;
    }
    return 0;
}

/*
 * Returns pointer into either 1D or 2D voice-state table.
 */
u8* inpGetChannelDefaults(u8 channel, u8 key)
{
    if (key == INP_INVALID_SLOT)
    {
        return &gInpChannelDefaults[channel];
    }
    return &gInpChannelDefaultsByKey[key][channel];
}

/*
 * Stores 2 into voice-state slot (1D or 2D variant).
 */
void inpResetChannelDefaults(u8 channel, u8 key)
{
    u8* p;
    if (key != INP_INVALID_SLOT)
    {
        p = &gInpChannelDefaultsByKey[key][channel];
    }
    else
    {
        p = &gInpChannelDefaults[channel];
    }
    *p = 2;
}

void inpAddCtrl(McmdInputSlot* dest, u8 ctrl, s32 scale, u8 comb, u32 isVar)
{
    u8 n;

    if (comb == 0)
    {
        dest->numSource = 0;
    }
    if (dest->numSource < 4)
    {
        n = dest->numSource++;
        if (isVar == 0)
        {
            ctrl = inpTranslateExCtrl(ctrl);
        }
        else
        {
            comb |= 0x10;
        }
        dest->source[n].midiCtrl = ctrl;
        dest->source[n].combine = comb;
        dest->source[n].scale = scale;
    }
}

/*
 * Copy one FX controller value between two voice slots' global controller banks.
 */
void inpFXCopyCtrl(u8 controller, McmdVoiceState* dstState, McmdVoiceState* srcState)
{
    u32 ctrl;
    u32 dstVoice;
    u32 srcVoice;
    u8* stateBase;
    u8* bank;

    ctrl = controller & 0xff;
    stateBase = (u8*)lbl_803CD760;
    dstVoice = dstState->id & 0xff;
    srcVoice = srcState->id & 0xff;

    if (ctrl < 0x40)
    {
        ctrl = controller & 0x1f;
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        bank = stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + 0x20;
        *(bank + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) = *(bank + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        return;
    }
    if (controller == MCMD_CTRL_PITCH_BEND || controller == MCMD_CTRL_PITCH_BEND + 1)
    {
        ctrl = controller & 0xfe;
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        bank = stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + 1;
        *(bank + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) = *(bank + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        return;
    }
    if (controller == MCMD_CTRL_DOPPLER || controller == MCMD_CTRL_DOPPLER + 1)
    {
        ctrl = controller & 0xfe;
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        bank = stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + 1;
        *(bank + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) = *(bank + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        return;
    }
    *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
}

/*
 * Set a byte in either gInpMidiLastNote[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 */
void inpSetMidiLastNote(u8 channel, u8 key, u8 v)
{
    if (key != INP_INVALID_SLOT)
    {
        lbl_803CD760[key][channel] = v;
    }
    else
    {
        gInpMidiLastNote[channel] = v;
    }
}

/*
 * Get a byte from either gInpMidiLastNote[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 */
u8 inpGetMidiLastNote(u8 channel, u8 key)
{
    if (key != INP_INVALID_SLOT)
    {
        return lbl_803CD760[key][channel];
    }
    return gInpMidiLastNote[channel];
}

/*
 * Evaluate a controller expression list and cache its 14-bit result.
 */
static u16 _GetInputValue(McmdVoiceState* statePtr, McmdInputSlot* slotPtr, u8 midi, u8 midiSet)
{
    u32 sign;
    u32 i;
    u32 value;
    u8 ctrl;
    s32 tmp;
    s32 vtmp;

    for (value = 0, i = 0; i < slotPtr->numSource; ++i)
    {
        if (slotPtr->source[i].combine & MCMD_INPUT_ENTRY_USE_VAR_FLAG)
        {
            tmp = (statePtr != NULL ? varGet(statePtr, 0, slotPtr->source[i].midiCtrl) : 0);
            goto combine_signed;
        }
        ctrl = slotPtr->source[i].midiCtrl;
        if (ctrl == MCMD_CTRL_PITCH_BEND || ctrl == MCMD_CTRL_MODULATION || ctrl == MCMD_CTRL_PANNING ||
            ctrl == MCMD_CTRL_EX_A0 || ctrl == MCMD_CTRL_EX_A1 || ctrl == MCMD_CTRL_SUR_PANNING)
        {
            switch (ctrl)
            {
            case MCMD_CTRL_EX_A0:
            case MCMD_CTRL_EX_A1:
                if (statePtr != NULL)
                {
                    tmp = statePtr->lfo[ctrl - MCMD_CTRL_EX_A0].value << 1;
                    statePtr->lfoUsedByInput[ctrl - MCMD_CTRL_EX_A0] = 1;
                }
                else
                {
                    tmp = 0;
                }
                break;
            default:
                tmp = (inpGetMidiCtrl(ctrl, midi, midiSet) & 0xffff) - 0x2000;
                break;
            }
        combine_signed:
            tmp = (tmp * (slotPtr->source[i].scale >> 1)) >> 15;
            if (tmp < -0x2000)
            {
                tmp = -0x2000;
            }
            else if (tmp > 0x1FFF)
            {
                tmp = 0x1FFF;
            }
            switch (slotPtr->source[i].combine & MCMD_INPUT_ENTRY_COMBINE_MASK)
            {
            case MCMD_INPUT_COMBINE_SET:
                value = tmp + 0x2000;
                sign = 1;
                break;
            case MCMD_INPUT_COMBINE_ADD:
                if (sign != 0)
                {
                    vtmp = (value + tmp);
                    vtmp -= 0x2000;
                    if (vtmp < -0x2000)
                    {
                        vtmp = -0x2000;
                    }
                    else if (vtmp > 0x1FFF)
                    {
                        vtmp = 0x1FFF;
                    }
                    value = vtmp + 0x2000;
                }
                else
                {
                    vtmp = value + tmp;
                    value = (vtmp > 0x3FFF) ? 0x3FFF : (vtmp < 0) ? 0 : vtmp;
                }
                break;
            case MCMD_INPUT_COMBINE_MUL:
                if (sign != 0)
                {
                    vtmp = (s32)((value - 0x2000) * tmp) >> 13;
                }
                else
                {
                    vtmp = (tmp * value) >> 13;
                    sign = 1;
                }
                if (vtmp < -0x2000)
                {
                    vtmp = -0x2000;
                }
                else if (vtmp > 0x1FFF)
                {
                    vtmp = 0x1FFF;
                }
                value = vtmp + 0x2000;
                break;
            case MCMD_INPUT_COMBINE_SUB:
                if (sign != 0)
                {
                    vtmp = (value - 0x2000) - tmp;
                    if (vtmp < -0x2000)
                    {
                        vtmp = -0x2000;
                    }
                    else if (vtmp > 0x1FFF)
                    {
                        vtmp = 0x1FFF;
                    }
                    value = vtmp + 0x2000;
                }
                else
                {
                    vtmp = value - tmp;
                    value = (vtmp > 0x3FFF) ? 0x3FFF : (vtmp < 0) ? 0 : vtmp;
                }
                break;
            }
        }
        else
        {
            ctrl = slotPtr->source[i].midiCtrl;
            switch (ctrl)
            {
            case MCMD_CTRL_MIDI_LAYER:
                if (statePtr != NULL)
                {
                    tmp = statePtr->orgNote << 7;
                }
                else
                {
                    tmp = 0;
                }
                break;
            case MCMD_CTRL_VOICE_AGE:
                tmp = statePtr != NULL ? statePtr->orgVolume >> 9 : 0;
                break;
            case MCMD_CTRL_VOICE_TIME:
                if (statePtr != NULL)
                {
                    tmp = (synthRealTime - *(u64*)&statePtr->macStartTimeHi) >> 8;
                    if (tmp > 0x3fff)
                    {
                        tmp = 0x3fff;
                    }
                    statePtr->timeUsedByInput = 1;
                }
                else
                {
                    tmp = 0;
                }
                break;
            default:
                tmp = inpGetMidiCtrl(ctrl, midi, midiSet) & 0xffff;
                break;
            }
            tmp = (tmp * (slotPtr->source[i].scale >> 1)) >> 15;
            if (tmp > 0x3FFF)
            {
                tmp = 0x3FFF;
            }
            switch (slotPtr->source[i].combine & MCMD_INPUT_ENTRY_COMBINE_MASK)
            {
            case MCMD_INPUT_COMBINE_SET:
                value = tmp;
                sign = 0;
                break;
            case MCMD_INPUT_COMBINE_ADD:
                if (sign != 0)
                {
                    vtmp = (value + tmp);
                    vtmp -= 0x2000;
                    if (vtmp < -0x2000)
                    {
                        vtmp = -0x2000;
                    }
                    else if (vtmp > 0x1FFF)
                    {
                        vtmp = 0x1FFF;
                    }
                    value = vtmp + 0x2000;
                }
                else
                {
                    value += tmp;
                    value = (value > 0x3FFF) ? 0x3FFF : value;
                }
                break;
            case MCMD_INPUT_COMBINE_MUL:
                if (sign != 0)
                {
                    vtmp = (s32)(tmp * (value - 0x2000)) >> 14;
                    if (vtmp < -0x2000)
                    {
                        vtmp = -0x2000;
                    }
                    else if (vtmp > 0x1FFF)
                    {
                        vtmp = 0x1FFF;
                    }
                    value = vtmp + 0x2000;
                }
                else
                {
                    value = ((value * tmp) >> 0xE);
                    value = (value > 0x3FFF) ? 0x3FFF : value;
                }
                break;
            case MCMD_INPUT_COMBINE_SUB:
                if (sign != 0)
                {
                    vtmp = (value - 0x2000) - tmp;
                    if (vtmp < -0x2000)
                    {
                        vtmp = -0x2000;
                    }
                    else if (vtmp > 0x1FFF)
                    {
                        vtmp = 0x1FFF;
                    }
                    value = vtmp + 0x2000;
                }
                else
                {
                    vtmp = value - tmp;
                    value = (vtmp > 0x3FFF) ? 0x3FFF : (vtmp < 0) ? 0 : vtmp;
                }
                break;
            }
        }
    }

    *(u16*)&slotPtr->oldValue = value;
    return value;
}

/*
 * Volume accessor: bit 0x1, slot at +0x218, cached u16 at +0x238.
 */
u16 inpGetVolume(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_VOLUME) == 0)
    {
        return state->inpVolume.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_VOLUME;
    return _GetInputValue(state, &state->inpVolume, state->midi, state->midiSet);
}

/*
 * Panning accessor: bit 0x2, slot at +0x23c, cached u16 at +0x25c.
 */
u16 inpGetPanning(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PANNING) == 0)
    {
        return state->inpPanning.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PANNING;
    return _GetInputValue(state, &state->inpPanning, state->midi, state->midiSet);
}

u16 inpGetSurPanning(McmdVoiceState* state)
{
    int flags;

    flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_SUR_PANNING) == 0)
    {
        return *(u16*)&state->inpSurroundPanning.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_SUR_PANNING;
    return _GetInputValue(state, &state->inpSurroundPanning, state->midi, state->midiSet);
}

u16 inpGetPitchBend(McmdVoiceState* state)
{
    int flags;

    flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PITCH_BEND) == 0)
    {
        return *(u16*)&state->inpPitchBend.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PITCH_BEND;
    return _GetInputValue(state, &state->inpPitchBend, state->midi, state->midiSet);
}

u16 inpGetDoppler(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_DOPPLER) == 0)
    {
        return state->inpDoppler.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_DOPPLER;
    return _GetInputValue(state, &state->inpDoppler, state->midi, state->midiSet);
}

u16 inpGetModulation(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_MODULATION) == 0)
    {
        return state->inpModulation.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_MODULATION;
    return _GetInputValue(state, &state->inpModulation, state->midi, state->midiSet);
}

u16 inpGetPedal(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PEDAL) == 0)
    {
        return state->inpPedal.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PEDAL;
    return _GetInputValue(state, &state->inpPedal, state->midi, state->midiSet);
}

u16 inpGetPreAuxA(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PRE_AUX_A) == 0)
    {
        return state->inpPreAuxA.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PRE_AUX_A;
    return _GetInputValue(state, &state->inpPreAuxA, state->midi, state->midiSet);
}

u16 inpGetReverb(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_REVERB) == 0)
    {
        return state->inpReverb.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_REVERB;
    return _GetInputValue(state, &state->inpReverb, state->midi, state->midiSet);
}

u16 inpGetPreAuxB(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PRE_AUX_B) == 0)
    {
        return state->inpPreAuxB.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PRE_AUX_B;
    return _GetInputValue(state, &state->inpPreAuxB, state->midi, state->midiSet);
}

u32 inpAuxADirtyFlags[4] = {0x80000001, 0x80000002, 0x80000004, 0x80000008};
u32 inpAuxBDirtyFlags[4] = {0x80000010, 0x80000020, 0x80000040, 0x80000080};


/*
 * Bit-11 (0x800) accessor - slot at +0x3a4, cached u16 at +0x3c4.
 */
u16 inpGetPostAuxB(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_POST_AUX_B) == 0)
    {
        return state->inpPostAuxB.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_POST_AUX_B;
    return _GetInputValue(state, &state->inpPostAuxB, state->midi, state->midiSet);
}

/*
 * Bit-12 (0x1000) accessor - slot at +0x3c8, cached u16 at +0x3e8.
 */
u16 inpGetTremolo(McmdVoiceState* state)
{
    u32 flags = state->midiDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_TREMOLO) == 0)
    {
        return state->inpTremolo.oldValue;
    }
    state->midiDirtyFlags = flags & ~MCMD_INPUT_DIRTY_TREMOLO;
    return _GetInputValue(state, &state->inpTremolo, state->midi, state->midiSet);
}

static inline u32 inpResetGlobalMIDIDirtyFlag(u8 chan, u8 midiSet, u32 flag)
{
    u32 ret;

    if ((ret = (flag & ((u32(*)[16])lbl_803D3CA0)[midiSet][chan]) != 0) != 0)
    {
        ((u32(*)[16])lbl_803D3CA0)[midiSet][chan] &= ~flag;
    }
    return ret;
}

/*
 * Cached aux A input getter for a studio/channel/slot.
 */
u16 inpGetAuxA(u8 studio, u8 index, u8 midi, u8 midiSet)
{
    if (!inpResetGlobalMIDIDirtyFlag(midi, midiSet, inpAuxADirtyFlags[index]))
    {
        return inpAuxA[studio][index].oldValue;
    }
    return _GetInputValue(0, &inpAuxA[studio][index], midi, midiSet);
}

/*
 * Cached aux B input getter for a studio/channel/slot.
 */
u16 inpGetAuxB(u8 studio, u8 index, u8 midi, u8 midiSet)
{
    if (!inpResetGlobalMIDIDirtyFlag(midi, midiSet, inpAuxBDirtyFlags[index]))
    {
        return inpAuxB[studio][index].oldValue;
    }
    return _GetInputValue(0, &inpAuxB[studio][index], midi, midiSet);
}

static inline void inpResetGlobalMIDIDirtyFlags(void)
{
    u32 i;
    u32 j;

    for (i = 0; i < 8; ++i)
    {
        for (j = 0; j < 16; ++j)
        {
            ((u32(*)[16])lbl_803D3CA0)[i][j] = 0xff;
        }
    }
}

/*
 * Input/controller state init.
 */
void inpInit(McmdVoiceState* vs)
{
    if (vs != NULL)
    {
        vs->inpVolume.source[0].midiCtrl = MCMD_CTRL_VOLUME;
        vs->inpVolume.source[0].combine = 0;
        vs->inpVolume.source[0].scale = 0x10000;
        vs->inpVolume.source[1].midiCtrl = MCMD_CTRL_EXPRESSION;
        vs->inpVolume.source[1].combine = 2;
        vs->inpVolume.source[1].scale = 0x10000;
        vs->inpVolume.numSource = 2;
        vs->inpPanning.source[0].midiCtrl = MCMD_CTRL_PANNING;
        vs->inpPanning.source[0].combine = 0;
        vs->inpPanning.source[0].scale = 0x10000;
        vs->inpPanning.numSource = 1;
        vs->inpSurroundPanning.source[0].midiCtrl = MCMD_CTRL_SUR_PANNING;
        vs->inpSurroundPanning.source[0].combine = 0;
        vs->inpSurroundPanning.source[0].scale = 0x10000;
        vs->inpSurroundPanning.numSource = 1;
        vs->inpPitchBend.source[0].midiCtrl = MCMD_CTRL_PITCH_BEND;
        vs->inpPitchBend.source[0].combine = 0;
        vs->inpPitchBend.source[0].scale = 0x10000;
        vs->inpPitchBend.numSource = 1;
        vs->inpModulation.source[0].midiCtrl = MCMD_CTRL_MODULATION;
        vs->inpModulation.source[0].combine = 0;
        vs->inpModulation.source[0].scale = 0x10000;
        vs->inpModulation.numSource = 1;
        vs->inpPedal.source[0].midiCtrl = MCMD_CTRL_PEDAL;
        vs->inpPedal.source[0].combine = 0;
        vs->inpPedal.source[0].scale = 0x10000;
        vs->inpPedal.numSource = 1;
        vs->inpPortamento.source[0].midiCtrl = MCMD_CTRL_PORTAMENTO;
        vs->inpPortamento.source[0].combine = 0;
        vs->inpPortamento.source[0].scale = 0x10000;
        vs->inpPortamento.numSource = 1;
        vs->inpPreAuxA.numSource = 0;
        vs->inpReverb.source[0].midiCtrl = MCMD_CTRL_REVERB;
        vs->inpReverb.source[0].combine = 0;
        vs->inpReverb.source[0].scale = 0x10000;
        vs->inpReverb.numSource = 1;
        vs->inpPreAuxB.numSource = 0;
        vs->inpPostAuxB.source[0].midiCtrl = MCMD_CTRL_POST_AUX_B;
        vs->inpPostAuxB.source[0].combine = 0;
        vs->inpPostAuxB.source[0].scale = 0x10000;
        vs->inpPostAuxB.numSource = 1;
        vs->inpDoppler.source[0].midiCtrl = MCMD_CTRL_DOPPLER;
        vs->inpDoppler.source[0].combine = 0;
        vs->inpDoppler.source[0].scale = 0x10000;
        vs->inpDoppler.numSource = 1;
        vs->inpTremolo.numSource = 0;
        vs->midiDirtyFlags = MCMD_INPUT_DIRTY_ALL;
        vs->lfoUsedByInput[0] = 0;
        vs->lfoUsedByInput[1] = 0;
        vs->timeUsedByInput = 0;
    }
    else
    {
        u32 i;
        u32 j;

        for (i = 0; i < 8; i++)
        {
            for (j = 0; j < 4; j++)
            {
                inpAuxA[i][j].numSource = 0;
                inpAuxB[i][j].numSource = 0;
            }
        }

        inpResetGlobalMIDIDirtyFlags();
    }
}

/*
 * Map an input byte (0x80..0x88) to a packed table value via a
 * jumptable, falling through for inputs outside that range.
 */
u8 inpTranslateExCtrl(u8 ctrl)
{
    switch (ctrl)
    {
    case 0x80:
        ctrl = MCMD_CTRL_PITCH_BEND;
        break;
    case 0x81:
        ctrl = 0x82;
        break;
    case 0x82:
        ctrl = MCMD_CTRL_EX_A0;
        break;
    case 0x83:
        ctrl = MCMD_CTRL_EX_A1;
        break;
    case 0x84:
        ctrl = MCMD_CTRL_SUR_PANNING;
        break;
    case 0x85:
        ctrl = MCMD_CTRL_DOPPLER;
        break;
    case 0x86:
        ctrl = MCMD_CTRL_MIDI_LAYER;
        break;
    case 0x87:
        ctrl = MCMD_CTRL_VOICE_AGE;
        break;
    case 0x88:
        ctrl = MCMD_CTRL_VOICE_TIME;
        break;
    }
    return ctrl;
}


u16 inpGetExCtrl(McmdVoiceState* state, u8 ctrl)
{
    u16 value;

    switch (inpTranslateExCtrl(ctrl))
    {
    case MCMD_CTRL_EX_A0:
        return state->lfo[0].value * 2 + 0x2000;
    case MCMD_CTRL_EX_A1:
        return state->lfo[1].value * 2 + 0x2000;
    default:
        if (state->midi != 0xff)
        {
            value = inpGetMidiCtrl(ctrl, state->midi, state->midiSet) & 0xffff;
        }
        else
        {
            value = 0;
        }
        return value & 0xffff;
    }
}

/*
 * Clamp and write an extended controller through MIDI for non-local controls.
 */
void inpSetExCtrl(McmdVoiceState* state, u8 ctrl, s16 value)
{
    value = value < 0 ? 0 : value > 0x3fff ? 0x3fff : value;
    switch (inpTranslateExCtrl(ctrl))
    {
    case MCMD_CTRL_EX_A1:
    case MCMD_CTRL_EX_A0:
        break;
    default:
        if (state->midi != 0xff)
        {
            inpSetMidiCtrl14(ctrl, state->midi, state->midiSet, value);
        }
        break;
    }
}
