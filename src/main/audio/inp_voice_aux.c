#include "main/audio/inp_ctrl.h"

u16 inpGetDoppler(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_DOPPLER) == 0)
    {
        return state->dopplerInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_DOPPLER;
    return _GetInputValue(state, &state->dopplerInput, state->midiSlot, state->midiEvent);
}

u16 inpGetModulation(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_MODULATION) == 0)
    {
        return state->modulationInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_MODULATION;
    return _GetInputValue(state, &state->modulationInput, state->midiSlot, state->midiEvent);
}

u16 inpGetPedal(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PEDAL) == 0)
    {
        return state->pedalInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PEDAL;
    return _GetInputValue(state, &state->pedalInput, state->midiSlot, state->midiEvent);
}

u16 inpGetPreAuxA(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PRE_AUX_A) == 0)
    {
        return state->preAuxAInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PRE_AUX_A;
    return _GetInputValue(state, &state->preAuxAInput, state->midiSlot, state->midiEvent);
}

u16 inpGetReverb(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_REVERB) == 0)
    {
        return state->reverbInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_REVERB;
    return _GetInputValue(state, &state->reverbInput, state->midiSlot, state->midiEvent);
}

u16 inpGetPreAuxB(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PRE_AUX_B) == 0)
    {
        return state->preAuxBInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PRE_AUX_B;
    return _GetInputValue(state, &state->preAuxBInput, state->midiSlot, state->midiEvent);
}
