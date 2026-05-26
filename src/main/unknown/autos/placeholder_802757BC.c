#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/unknown/autos/placeholder_802757BC.h"

extern u32 sndRand(void);
extern u32 hwIsActive(u8 voiceId);

/*
 * --INFO--
 *
 * Function: mcmdLoop
 * EN v1.0 Address: 0x8027566C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802757BC
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mcmdLoop(McmdVoiceState *state, McmdCommandArgs *params)
{
    u16 counter;
    u32 zero;
    u32 flags;

    if (state->loopCounter == 0) {
        if (((params->flags >> 16) & 1) != 0) {
            state->loopCounter = (u16)sndRand() % (u16)(params->value >> 16);
        } else {
            state->loopCounter = (u16)(params->value >> 16);
        }
        if (state->loopCounter == MCMD_LOOP_COUNTER_FOREVER) {
            goto check_flags;
        }
        state->loopCounter = state->loopCounter + 1;
    } else {
        if (state->loopCounter == MCMD_LOOP_COUNTER_FOREVER) {
            goto check_flags;
        }
    }
    counter = state->loopCounter - 1;
    state->loopCounter = counter;
    if (counter == 0) {
        return;
    }

check_flags:
    flags = params->flags;
    if (((flags >> 8) & 1) != 0) {
        zero = 0;
        if (((state->inputFlags & MCMD_VOICE_KEYOFF_INPUT_FLAG) == zero) &&
            ((state->outputFlags & MCMD_VOICE_KEYOFF_OUTPUT_FLAG) ==
             MCMD_VOICE_KEYOFF_OUTPUT_FLAG)) {
            state->loopCounter = 0;
            return;
        }
    }
    if (((flags >> 24) & 1) != 0) {
        zero = 0;
        if (((state->inputFlags & zero) == zero) &&
            ((state->outputFlags & MCMD_VOICE_ACTIVE_OUTPUT_FLAG) == zero)) {
            if (hwIsActive(state->voiceHandle & 0xff) == 0) {
                state->loopCounter = zero;
                return;
            }
        }
    }
    state->macroCursor = state->macroBase + ((params->value & 0xffff) << 3);
}
