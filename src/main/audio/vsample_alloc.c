#include "main/audio/synth_virtual_sample.h"
#include "main/audio/aram.h"

#pragma exceptions on

/*
 * Reset the virtual sample stream buffer table.
 */
void synthInitVirtualSampleTable(void)
{
    int i;
    SynthVirtualSampleState* state = &synthVirtualSampleState;

    state->entryCount = 0;
    for (i = 0; i < SYNTH_VIRTUAL_SAMPLE_MAX_VOICES; i++)
    {
        state->voiceMap[i] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
    }
    state->nextId = 0;
    state->callback = 0;
}

static inline void vsFreeBuffer(SynthVirtualSampleState* state, u8 entryIndex)
{
    state->entries[entryIndex].mode = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
    state->voiceMap[state->entries[entryIndex].voice] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

static inline u8 vsAllocateBuffer(SynthVirtualSampleState* state)
{
    u8 i;

    for (i = 0; i < state->entryCount; ++i)
    {
        if (state->entries[i].mode != SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE)
        {
            continue;
        }
        state->entries[i].mode = SYNTH_VIRTUAL_SAMPLE_MODE_ACTIVE;
        state->entries[i].position = 0;
        return i;
    }

    return SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

static inline u16 vsNewInstanceID(SynthVirtualSampleState* state)
{
    u8 i;
    u16 instID;

    do
    {
        instID = state->nextId++;
        for (i = 0; i < state->entryCount; ++i)
        {
            if (state->entries[i].mode != SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE &&
                state->entries[i].callbackData.generation == instID)
            {
                break;
            }
        }
    } while (i != state->entryCount);

    return instID;
}

/*
 * Allocate a stream buffer for the voice and set up its virtual sample
 * loop buffer.
 */
u32 synthClaimVirtualSampleSlot(u8 voiceID)
{
    SynthVirtualSampleState* state[1];
    u8 sb;
    u8 i;
    u32 addr;

    state[0] = &synthVirtualSampleState;

    for (i = 0; i < state[0]->entryCount; ++i)
    {
        if (state[0]->entries[i].mode != SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE && state[0]->entries[i].voice == voiceID)
        {
            vsFreeBuffer(state[0], i);
        }
    }

    sb = state[0]->voiceMap[voiceID] = vsAllocateBuffer(state[0]);
    if (sb != SYNTH_VIRTUAL_SAMPLE_FREE_SLOT)
    {
        addr = aramGetStreamBufferAddress(state[0]->voiceMap[voiceID], 0);
        hwSetVirtualSampleLoopBuffer(voiceID, addr, state[0]->loopSize);
        state[0]->entries[sb].callbackData.sampleId = hwGetSampleID(voiceID);
        state[0]->entries[sb].callbackData.generation = vsNewInstanceID(state[0]);
        state[0]->entries[sb].type = hwGetSampleType(voiceID);
        state[0]->entries[sb].voice = voiceID;
        if (state[0]->callback != 0)
        {
            state[0]->callback(SYNTH_VIRTUAL_SAMPLE_CLAIM_CALLBACK_KIND, &state[0]->entries[sb].callbackData);
            return (state[0]->entries[sb].callbackData.generation << 8) | (u8)voiceID;
        }
        hwSetVirtualSampleLoopBuffer(voiceID, 0, 0);
    }
    else
    {
        hwSetVirtualSampleLoopBuffer(voiceID, 0, 0);
    }

    return SYNTH_VIRTUAL_SAMPLE_INVALID_ID;
}
