#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80282288.h"

extern u32 inpGetMidiCtrl(u8 controller, u32 slot, u32 key);
extern int varGet(int state, int useExCtrl, u32 index);
extern u32 synthRealTimeHi;
extern u32 synthRealTimeLo;

/*
 * Evaluate a controller expression list and cache its 14-bit result.
 */
u16 _GetInputValue(McmdVoiceState *statePtr, McmdInputSlot *slotPtr, u8 midiSlot, u8 midiKey)
{
    int state;
    McmdInputEntry *entry;
    u32 value;
    u32 result;
    u32 i;
    int signedMode;

    state = (int)statePtr;
    result = 0;
    i = 0;
    entry = slotPtr->entries;
    signedMode = 0;
    do {
        if (slotPtr->entryCount <= i) {
            slotPtr->cachedValue = (s16)result;
            return result & 0xffff;
        }
        if ((entry->combineModeFlags & MCMD_INPUT_ENTRY_USE_VAR_FLAG) == 0) {
            u8 ctrl = entry->controller;
            if (ctrl == MCMD_CTRL_PITCH_BEND || ctrl == MCMD_CTRL_MODULATION ||
                ctrl == MCMD_CTRL_PANNING || (u8)(ctrl + 0x60) < 2 ||
                ctrl == MCMD_CTRL_SUR_PANNING) {
                if (ctrl < MCMD_CTRL_MIDI_LAYER && ctrl > 0x9f) {
                    int signedValue;
                    if (statePtr == NULL) {
                        signedValue = 0;
                    } else {
                        signedValue = statePtr->exCtrls[ctrl - MCMD_CTRL_EX_A0].value << 1;
                        statePtr->exCtrlDirty[ctrl - MCMD_CTRL_EX_A0] = 1;
                    }
                    value = signedValue;
                    goto signed_input;
                } else {
                    value = (inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff) - 0x2000;
                    goto signed_input;
                }
            }

            if (ctrl == MCMD_CTRL_VOICE_AGE) {
                if (statePtr == NULL) {
                    value = 0;
                } else {
                    value = *(u32 *)(state + 0x158) >> 9;
                }
            } else if (ctrl < MCMD_CTRL_VOICE_AGE) {
                if (ctrl < MCMD_CTRL_MIDI_LAYER) {
                    value = inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff;
                } else if (statePtr == NULL) {
                    value = 0;
                } else {
                    value = (u32)statePtr->midiLayer << 7;
                }
            } else {
                if (ctrl > 0xa4) {
                    value = inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff;
                } else if (statePtr == NULL) {
                    value = 0;
                } else {
                    u32 hi = synthRealTimeHi -
                             ((u32)(synthRealTimeLo < statePtr->startTimeLo) +
                              statePtr->startTimeHi);
                    u32 lo = synthRealTimeLo - statePtr->startTimeLo;
                    value = (u32)((((u64)hi << 32) | lo) >> 8);
                    if ((int)value > 0x3fff) {
                        value = 0x3fff;
                    }
                    statePtr->unkA8[0] = 1;
                }
            }

            value = (int)(value * (entry->scale >> 1)) >> 0xf;
            if ((int)value > 0x3fff) {
                value = 0x3fff;
            }
            switch (entry->combineModeFlags & MCMD_INPUT_ENTRY_COMBINE_MASK) {
            case MCMD_INPUT_COMBINE_SET:
                signedMode = 0;
                result = value;
                break;
            case MCMD_INPUT_COMBINE_ADD:
                if (signedMode == 0) {
                    result += value;
                    if (result > 0x3fff) {
                        result = 0x3fff;
                    }
                } else {
                    int v = result + value - 0x2000;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            case MCMD_INPUT_COMBINE_MUL:
                if (signedMode == 0) {
                    result = (result * value) >> 0xe;
                    if (result > 0x3fff) {
                        result = 0x3fff;
                    }
                } else {
                    int v = (int)(value * (result - 0x2000)) >> 0xe;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            case MCMD_INPUT_COMBINE_SUB:
                if (signedMode == 0) {
                    result -= value;
                    if ((int)result >= 0x4000) {
                        result = 0x3fff;
                    } else if ((int)result < 0) {
                        result = 0;
                    }
                } else {
                    int v = (result - 0x2000) - value;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            }
        } else {
            int signedValue;
            if (statePtr == NULL) {
                signedValue = 0;
            } else {
                signedValue = varGet(state, 0, entry->controller);
            }
signed_input:
            signedValue = (int)(signedValue * (entry->scale >> 1)) >> 0xf;
            if (signedValue < -0x2000) {
                signedValue = -0x2000;
            } else if (signedValue > 0x1fff) {
                signedValue = 0x1fff;
            }
            switch (entry->combineModeFlags & MCMD_INPUT_ENTRY_COMBINE_MASK) {
            case MCMD_INPUT_COMBINE_SET:
                signedMode = 1;
                result = signedValue + 0x2000;
                break;
            case MCMD_INPUT_COMBINE_ADD:
                if (signedMode == 0) {
                    result += signedValue;
                    if ((int)result >= 0x4000) {
                        result = 0x3fff;
                    } else if ((int)result < 0) {
                        result = 0;
                    }
                } else {
                    int v = result + signedValue - 0x2000;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            case MCMD_INPUT_COMBINE_MUL:
                if (signedMode == 0) {
                    result = (signedValue * result) >> 0xd;
                    signedMode = 1;
                } else {
                    result = (int)((result - 0x2000) * signedValue) >> 0xd;
                }
                if ((int)result < -0x2000) {
                    result = 0xffffe000;
                } else if ((int)result > 0x1fff) {
                    result = 0x1fff;
                }
                result += 0x2000;
                break;
            case MCMD_INPUT_COMBINE_SUB:
                if (signedMode == 0) {
                    result -= signedValue;
                    if ((int)result >= 0x4000) {
                        result = 0x3fff;
                    } else if ((int)result < 0) {
                        result = 0;
                    }
                } else {
                    int v = (result - 0x2000) - signedValue;
                    if (v < -0x2000) {
                        v = -0x2000;
                    } else if (v > 0x1fff) {
                        v = 0x1fff;
                    }
                    result = v + 0x2000;
                }
                break;
            }
        }
        entry++;
        i++;
    } while (1);
}

/*
 * Volume accessor: bit 0x1, slot at +0x218, cached u16 at +0x238.
 *
 * EN v1.0 Address: 0x80282078
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802824F8
 * EN v1.1 Size: 72b
 */
u16 inpGetVolume(McmdVoiceState *state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_VOLUME) == 0) {
        return state->volumeInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_VOLUME;
    return _GetInputValue(state, &state->volumeInput, state->midiSlot, state->midiEvent);
}

/*
 * Panning accessor: bit 0x2, slot at +0x23c, cached u16 at +0x25c.
 *
 * EN v1.1 Address: 0x80282540
 * EN v1.1 Size: 72b
 */
u16 inpGetPanning(McmdVoiceState *state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PANNING) == 0) {
        return state->panningInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PANNING;
    return _GetInputValue(state, &state->panningInput, state->midiSlot, state->midiEvent);
}
