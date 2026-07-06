#include "main/audio/inp_ctrl.h"
#include "main/audio/inp_midi.h"

extern int varGet(int state, int useExCtrl, u32 index);
extern u32 synthRealTimeHi;

/*
 * Evaluate a controller expression list and cache its 14-bit result.
 */
u16 _GetInputValue(McmdVoiceState* statePtr, McmdInputSlot* slotPtr, u32 midiSlot, u32 midiKey)
{
    u32 sign;
    u32 i;
    u32 value;
    u8 ctrl;
    s32 tmp;
    s32 vtmp;

    for (value = 0, i = 0; i < slotPtr->entryCount; ++i)
    {
        if (slotPtr->entries[i].combineModeFlags & MCMD_INPUT_ENTRY_USE_VAR_FLAG)
        {
            tmp = (statePtr != NULL ? (s16)varGet((int)statePtr, 0, slotPtr->entries[i].controller) : 0);
            goto block_18;
        }
        ctrl = slotPtr->entries[i].controller;
        if (ctrl == MCMD_CTRL_PITCH_BEND || ctrl == MCMD_CTRL_MODULATION ||
            ctrl == MCMD_CTRL_PANNING || ctrl == MCMD_CTRL_EX_A0 ||
            ctrl == MCMD_CTRL_EX_A1 || ctrl == MCMD_CTRL_SUR_PANNING)
        {
            switch (ctrl)
            {
            case MCMD_CTRL_EX_A0:
            case MCMD_CTRL_EX_A1:
                if (statePtr != NULL)
                {
                    tmp = statePtr->exCtrls[ctrl - MCMD_CTRL_EX_A0].value << 1;
                    statePtr->exCtrlDirty[ctrl - MCMD_CTRL_EX_A0] = 1;
                }
                else
                {
                    tmp = 0;
                }
                break;
            default:
                tmp = (inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff) - 0x2000;
                break;
            }
        block_18:
            tmp = (tmp * (slotPtr->entries[i].scale >> 1)) >> 15;
            if (tmp < -0x2000)
            {
                tmp = -0x2000;
            }
            else if (tmp > 0x1FFF)
            {
                tmp = 0x1FFF;
            }
            switch (slotPtr->entries[i].combineModeFlags & MCMD_INPUT_ENTRY_COMBINE_MASK)
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
            switch (ctrl)
            {
            case MCMD_CTRL_MIDI_LAYER:
                if (statePtr != NULL)
                {
                    tmp = statePtr->keyBase << 7;
                }
                else
                {
                    tmp = 0;
                }
                break;
            case MCMD_CTRL_VOICE_AGE:
                tmp = statePtr != NULL ? statePtr->volumeBase >> 9 : 0;
                break;
            case 0xA4:
                if (statePtr != NULL)
                {
                    tmp = ((*(u64*)&synthRealTimeHi) - (*(u64*)&statePtr->startTimeHi)) >> 8;
                    if (tmp > 0x3fff)
                    {
                        tmp = 0x3fff;
                    }
                    statePtr->unkA8[0] = 1;
                }
                else
                {
                    tmp = 0;
                }
                break;
            default:
                tmp = inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff;
                break;
            }
            tmp = (tmp * (slotPtr->entries[i].scale >> 1)) >> 15;
            if (tmp > 0x3FFF)
            {
                tmp = 0x3FFF;
            }
            switch (slotPtr->entries[i].combineModeFlags & MCMD_INPUT_ENTRY_COMBINE_MASK)
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

    *(u16*)&slotPtr->cachedValue = value;
    return value;
}

/*
 * Volume accessor: bit 0x1, slot at +0x218, cached u16 at +0x238.
 */
u16 inpGetVolume(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_VOLUME) == 0)
    {
        return state->volumeInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_VOLUME;
    return _GetInputValue(state, &state->volumeInput, state->midiSlot, state->midiEvent);
}

/*
 * Panning accessor: bit 0x2, slot at +0x23c, cached u16 at +0x25c.
 */
u16 inpGetPanning(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PANNING) == 0)
    {
        return state->panningInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PANNING;
    return _GetInputValue(state, &state->panningInput, state->midiSlot, state->midiEvent);
}
