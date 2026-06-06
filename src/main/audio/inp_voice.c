#include "ghidra_import.h"
#include "main/audio/inp_ctrl.h"

/*
 * --INFO--
 *
 * Function: inpGetSurPanning
 * EN v1.0 Address: 0x80282588
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80282594
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int inpGetSurPanning(McmdVoiceState *state)
{
    /* recipe #57: int return - the inp_ctrl.h u16 prototype adds clrlwi */
    extern int _GetInputValue(McmdVoiceState *state, McmdInputSlot *slot, u8 midiSlot, u8 midiEvent);
    int flags;

    flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_SUR_PANNING) == 0) {
        return *(u16 *)&state->surPanningInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_SUR_PANNING;
    return _GetInputValue(state, &state->surPanningInput, state->midiSlot, state->midiEvent);
}

/*
 * --INFO--
 *
 * Function: inpGetPitchBend
 * EN v1.0 Address: 0x802825D0
 * EN v1.0 Size: 72b
 */
int inpGetPitchBend(McmdVoiceState *state)
{
    extern int _GetInputValue(McmdVoiceState *state, McmdInputSlot *slot, u8 midiSlot, u8 midiEvent);
    int flags;

    flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_PITCH_BEND) == 0) {
        return *(u16 *)&state->pitchBendInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_PITCH_BEND;
    return _GetInputValue(state, &state->pitchBendInput, state->midiSlot, state->midiEvent);
}
