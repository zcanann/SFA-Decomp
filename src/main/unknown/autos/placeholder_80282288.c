#include "ghidra_import.h"
#include "main/audio/inp_midi.h"
#include "main/unknown/autos/placeholder_80282288.h"

extern int varGet(int state, int useExCtrl, u32 index);
extern u64 __shr2u(u32 hi, u32 lo, u32 shift);
extern u32 synthRealTimeHi;
extern u32 synthRealTimeLo;

/*
 * Evaluate a controller expression list and cache its 14-bit result.
 */
u16 _GetInputValue(McmdVoiceState *statePtr, McmdInputSlot *slotPtr, u32 midiSlot, u32 midiKey)
{
    McmdInputEntry *entry;
    int signedValue;
    u32 ctrl;
    u32 result;
    u32 i;
    int signedMode;

    entry = slotPtr->entries;
    result = 0;
    i = 0;
    goto check_entry_count;

    while (1) {
        if ((entry->combineModeFlags & MCMD_INPUT_ENTRY_USE_VAR_FLAG) != 0) {
            if (statePtr == NULL) {
                signedValue = 0;
            } else {
                signedValue = (s16)varGet((int)statePtr, 0, entry->controller);
            }
            goto signed_input;
        }

        ctrl = entry->controller;
        if (ctrl == MCMD_CTRL_PITCH_BEND || ctrl == MCMD_CTRL_MODULATION ||
            ctrl == MCMD_CTRL_PANNING || (u8)(ctrl - MCMD_CTRL_EX_A0) <= 1 ||
            ctrl == MCMD_CTRL_SUR_PANNING) {
            if (ctrl >= MCMD_CTRL_EX_A0 && ctrl < MCMD_CTRL_MIDI_LAYER) {
                if (statePtr == NULL) {
                    signedValue = 0;
                } else {
                    signedValue = statePtr->exCtrls[ctrl - MCMD_CTRL_EX_A0].value << 1;
                    statePtr->exCtrlDirty[ctrl - MCMD_CTRL_EX_A0] = 1;
                }
            } else {
                signedValue = (inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff) - 0x2000;
            }
            goto signed_input;
        }

        if (ctrl == MCMD_CTRL_VOICE_AGE) {
            if (statePtr == NULL) {
                ctrl = 0;
            } else {
                ctrl = statePtr->volume >> 9;
            }
        } else if (ctrl < MCMD_CTRL_VOICE_AGE) {
            if (ctrl < MCMD_CTRL_MIDI_LAYER) {
                ctrl = inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff;
            } else if (statePtr == NULL) {
                ctrl = 0;
            } else {
                ctrl = (u32)statePtr->keyBase << 7;
            }
        } else {
            if (ctrl >= 0xa5) {
                ctrl = inpGetMidiCtrl(ctrl, midiSlot, midiKey) & 0xffff;
            } else if (statePtr == NULL) {
                ctrl = 0;
            } else {
                u32 realLo = synthRealTimeLo;
                u32 realHi = synthRealTimeHi;
                u32 startLo = statePtr->startTimeLo;
                u32 startHi = statePtr->startTimeHi;
                ctrl = (u32)__shr2u(realHi - startHi - (realLo < startLo),
                                    realLo - startLo, 8);
                if ((int)ctrl > 0x3fff) {
                    ctrl = 0x3fff;
                }
                statePtr->unkA8[0] = 1;
            }
        }

        ctrl = (int)(ctrl * (entry->scale >> 1)) >> 0xf;
        if ((int)ctrl > 0x3fff) {
            ctrl = 0x3fff;
        }
        switch (entry->combineModeFlags & MCMD_INPUT_ENTRY_COMBINE_MASK) {
        case MCMD_INPUT_COMBINE_SET:
            signedMode = 0;
            result = ctrl;
            break;
        case MCMD_INPUT_COMBINE_ADD:
            if (signedMode == 0) {
                result += ctrl;
                if (result > 0x3fff) {
                    result = 0x3fff;
                }
            } else {
                int v = result + ctrl - 0x2000;
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
                result = (result * ctrl) >> 0xe;
                if (result > 0x3fff) {
                    result = 0x3fff;
                }
            } else {
                int v = (int)(ctrl * (result - 0x2000)) >> 0xe;
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
                result -= ctrl;
                if ((int)result >= 0x4000) {
                    result = 0x3fff;
                } else if ((int)result < 0) {
                    result = 0;
                }
            } else {
                int v = (result - 0x2000) - ctrl;
                if (v < -0x2000) {
                    v = -0x2000;
                } else if (v > 0x1fff) {
                    v = 0x1fff;
                }
                result = v + 0x2000;
            }
            break;
        }

        goto advance_entry;

signed_input:
        signedValue = (int)(signedValue * (entry->scale >> 1)) >> 0xf;
        if (signedValue < -0x2000) {
            signedValue = -0x2000;
        } else if (signedValue > 0x1fff) {
            signedValue = 0x1fff;
        }
        switch (entry->combineModeFlags & MCMD_INPUT_ENTRY_COMBINE_MASK) {
        case MCMD_INPUT_COMBINE_SET:
            result = signedValue + 0x2000;
            signedMode = 1;
            break;
        case MCMD_INPUT_COMBINE_ADD:
            if (signedMode != 0) {
                signedValue = result + signedValue - 0x2000;
                if (signedValue < -0x2000) {
                    signedValue = -0x2000;
                } else if (signedValue > 0x1fff) {
                    signedValue = 0x1fff;
                }
                result = signedValue + 0x2000;
            } else {
                result += signedValue;
                if ((int)result >= 0x4000) {
                    result = 0x3fff;
                } else if ((int)result < 0) {
                    result = 0;
                }
            }
            break;
        case MCMD_INPUT_COMBINE_MUL:
            if (signedMode != 0) {
                signedValue = (int)((result - 0x2000) * signedValue) >> 0xd;
            } else {
                signedValue = (signedValue * result) >> 0xd;
                signedMode = 1;
            }
            if (signedValue < -0x2000) {
                signedValue = -0x2000;
            } else if (signedValue > 0x1fff) {
                signedValue = 0x1fff;
            }
            result = signedValue + 0x2000;
            break;
        case MCMD_INPUT_COMBINE_SUB:
            if (signedMode != 0) {
                signedValue = (result - 0x2000) - signedValue;
                if (signedValue < -0x2000) {
                    signedValue = -0x2000;
                } else if (signedValue > 0x1fff) {
                    signedValue = 0x1fff;
                }
                result = signedValue + 0x2000;
            } else {
                result -= signedValue;
                if ((int)result >= 0x4000) {
                    result = 0x3fff;
                } else if ((int)result < 0) {
                    result = 0;
                }
            }
            break;
        }

advance_entry:
        entry++;
        i++;

check_entry_count:
        if (i < slotPtr->entryCount) {
            continue;
        }
        break;
    }

    slotPtr->cachedValue = result;
    return result;
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
