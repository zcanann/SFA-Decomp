#include "ghidra_import.h"
#include "main/audio/inp_ctrl.h"

/*
 * --INFO--
 *
 * Function: inpGetDoppler
 * EN v1.0 Address: 0x80282618
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80282630
 * EN v1.1 Size: 72b
 */
u16 inpGetDoppler(McmdVoiceState *state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_DOPPLER) == 0) {
        return state->dopplerInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_DOPPLER;
    return _GetInputValue(state, &state->dopplerInput, state->midiSlot, state->midiEvent);
}

/*
 * Function: inpGetModulation
 */
u16 inpGetModulation(McmdVoiceState *state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_MODULATION) == 0) {
        return state->modulationInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_MODULATION;
    return _GetInputValue(state, &state->modulationInput, state->midiSlot, state->midiEvent);
}

/*
 * Function: inpGetPedal
 */
u16 inpGetPedal(McmdVoiceState *state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PEDAL) == 0) {
        return state->pedalInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PEDAL;
    return _GetInputValue(state, &state->pedalInput, state->midiSlot, state->midiEvent);
}

/*
 * Function: inpGetPreAuxA
 */
u16 inpGetPreAuxA(McmdVoiceState *state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PRE_AUX_A) == 0) {
        return state->preAuxAInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PRE_AUX_A;
    return _GetInputValue(state, &state->preAuxAInput, state->midiSlot, state->midiEvent);
}

/*
 * Function: inpGetReverb
 */
u16 inpGetReverb(McmdVoiceState *state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_REVERB) == 0) {
        return state->reverbInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_REVERB;
    return _GetInputValue(state, &state->reverbInput, state->midiSlot, state->midiEvent);
}

/*
 * Function: inpGetPreAuxB
 */
u16 inpGetPreAuxB(McmdVoiceState *state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PRE_AUX_B) == 0) {
        return state->preAuxBInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PRE_AUX_B;
    return _GetInputValue(state, &state->preAuxBInput, state->midiSlot, state->midiEvent);
}
