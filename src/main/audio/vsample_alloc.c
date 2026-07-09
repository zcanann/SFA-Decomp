#include "main/audio/synth_virtual_sample.h"
#include "main/audio/aram.h"

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

static void vsFreeBuffer(SynthVirtualSampleState* state, u8 entryIndex)
{
    state->entries[entryIndex].mode = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
    state->voiceMap[state->entries[entryIndex].voice] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

static u8 vsAllocateBuffer(SynthVirtualSampleState* state)
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

static u16 vsNewInstanceID(SynthVirtualSampleState* state)
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
    SynthVirtualSampleState* state = &synthVirtualSampleState;
    u8 sb;
    u8 i;
    u32 addr;

    for (i = 0; i < state->entryCount; ++i)
    {
        if (state->entries[i].mode != SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE && state->entries[i].voice == voiceID)
        {
            vsFreeBuffer(state, i);
        }
    }

    sb = state->voiceMap[voiceID] = vsAllocateBuffer(state);
    if (sb != SYNTH_VIRTUAL_SAMPLE_FREE_SLOT)
    {
        addr = aramGetStreamBufferAddress(state->voiceMap[voiceID], 0);
        hwSetVirtualSampleLoopBuffer(voiceID, addr, state->loopSize);
        state->entries[sb].callbackData.sampleId = hwGetSampleID(voiceID);
        state->entries[sb].callbackData.generation = vsNewInstanceID(state);
        state->entries[sb].type = hwGetSampleType(voiceID);
        state->entries[sb].voice = voiceID;
        if (state->callback != 0)
        {
            state->callback(SYNTH_VIRTUAL_SAMPLE_CLAIM_CALLBACK_KIND, &state->entries[sb].callbackData);
            return (state->entries[sb].callbackData.generation << 8) | (voiceID & 0xff);
        }
        hwSetVirtualSampleLoopBuffer(voiceID, 0, 0);
    }
    else
    {
        hwSetVirtualSampleLoopBuffer(voiceID, 0, 0);
    }

    return SYNTH_VIRTUAL_SAMPLE_INVALID_ID;
}
