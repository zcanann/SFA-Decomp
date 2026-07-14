#include "ghidra_import.h"
#include "main/audio/mcmd.h"

extern int _GetInputValue(McmdVoiceState* state, McmdInputSlot* slot, u8 midiSlot, u8 midiEvent);

#pragma exceptions on

int inpGetSurPanning(McmdVoiceState* state)
{
    int flags;

    flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_SUR_PANNING) == 0)
    {
        return *(u16*)&state->surPanningInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_SUR_PANNING;
    return _GetInputValue(state, &state->surPanningInput, state->midiSlot, state->midiEvent);
}

int inpGetPitchBend(McmdVoiceState* state)
{
    int flags;

    flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PITCH_BEND) == 0)
    {
        return *(u16*)&state->pitchBendInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PITCH_BEND;
    return _GetInputValue(state, &state->pitchBendInput, state->midiSlot, state->midiEvent);
}
