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
    if (((u8)(params->flags >> 8) & 1) != 0 &&
        (*(u64 *)&state->inputFlags & 0x10000000008ULL) == 0x00000000008ULL) {
        state->loopCounter = 0;
    } else if (((u8)(params->flags >> 24) & 1) != 0 &&
               (*(u64 *)&state->inputFlags & 0x20ULL) == 0 &&
               !hwIsActive(state->voiceHandle & 0xff)) {
        state->loopCounter = 0;
    } else {
        state->macroCursor = state->macroBase + ((params->value & 0xffff) << 3);
    }
}
