#include "main/audio/mcmd_loop.h"

#include "main/audio/hw_init.h"
#include "main/audio/snd_service.h"

void mcmdLoop(McmdVoiceState* state, McmdCommandArgs* params)
{
    u16 counter;

    counter = state->loopCounter;
    if (counter == 0)
    {
        if (((params->flags >> 16) & 1) != 0)
        {
            state->loopCounter = (u16)sndRand() % (u16)(params->value >> 16);
        }
        else
        {
            state->loopCounter = (u16)(params->value >> 16);
        }
        counter = state->loopCounter;
        if (counter != MCMD_LOOP_COUNTER_FOREVER)
        {
            state->loopCounter = state->loopCounter + 1;
        }
    }

    if (counter != MCMD_LOOP_COUNTER_FOREVER)
    {
        counter = state->loopCounter - 1;
        state->loopCounter = counter;
        if (counter == 0)
        {
            return;
        }
    }

    if (((u8)(params->flags >> 8) & 1) != 0 && (*(u64*)&state->inputFlags & 0x10000000008ULL) == 0x00000000008ULL)
    {
        state->loopCounter = 0;
    }
    else if (((u8)(params->flags >> 24) & 1) != 0 && (*(u64*)&state->inputFlags & 0x20ULL) == 0 &&
             !hwIsActive(state->voiceHandle & 0xff))
    {
        state->loopCounter = 0;
    }
    else
    {
        state->macroCursor = state->macroBase + ((params->value & 0xffff) << 3);
    }
}
