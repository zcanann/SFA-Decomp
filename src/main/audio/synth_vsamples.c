#include "main/audio/synth_virtual_sample.h"
#include "main/audio/aram.h"
#include "main/audio/vsample_update.h"
#include "main/audio/mcmd.h"
#include "main/audio/hw_stream.h"
#include "main/audio/hw_samplemem_api.h"

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

SynthVirtualSampleState synthVirtualSampleState;

/*
 * Sample-completion handler: if the packed (slotIdx, sampleId)
 * still matches the active sample, fire the global "done" callback
 * with kind=2, then clear the entry's mode and free the slot back to
 * the index pool.
 */
void synthHandleVirtualSampleDone(u32 packed)
{
    SynthVirtualSampleState* state;
    u8* entry;
    u32 entryOffset;
    u8* slots;
    u8 vid;
    u32 generation;

    state = &synthVirtualSampleState;
    if (packed == SYNTH_VIRTUAL_SAMPLE_INVALID_ID)
    {
        return;
    }
    vid = (slots = state->voiceMap)[(u8)packed];
    if (vid == SYNTH_VIRTUAL_SAMPLE_FREE_SLOT)
    {
        return;
    }
    entryOffset = vid * SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE;
    generation = (packed >> 8) & 0xffff;
    if (state->entries[vid].callbackData.generation != generation)
    {
        return;
    }
    if (state->callback != NULL)
    {
        state->callback(SYNTH_VIRTUAL_SAMPLE_DONE_CALLBACK_KIND, &state->entries[vid].callbackData);
    }
    entry = (u8*)state + entryOffset;
    *(u8*)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_MODE_OFFSET) =
        SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
    slots[*(u8*)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_VOICE_OFFSET)] =
        SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

void synthAdvanceVirtualSampleEntry(void* entry, u32 elapsed)
{
    SynthVirtualSampleState* state;
    SynthVirtualSampleEntry* sample;
    u32* loopSizePtr;
    struct
    {
        u32 len, off;
    } d; /* struct-typed pair claims target frame slot */

    state = &synthVirtualSampleState;
    sample = entry;
    if (sample->position == elapsed)
    {
        return;
    }
    if ((s32)sample->position < elapsed)
    {
        switch (sample->type)
        {
        case SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE:
            sample->callbackData.start =
                (sample->position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) * SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            sample->callbackData.size = elapsed - sample->position;
            sample->callbackData.wrapA = 0;
            sample->callbackData.wrapB = 0;
            if ((d.len = ((int (*)(int, void*))state->callback)(SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND,
                                                                &sample->callbackData)) != 0)
            {
                d.off = sample->position + d.len;
                sample->position = d.off % state->loopSize;
            }
            break;
        default:
            break;
        }
    }
    else if (elapsed == 0)
    {
        switch (sample->type)
        {
        case SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE:
            sample->callbackData.start =
                (sample->position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) * SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            loopSizePtr = &state->loopSize;
            sample->callbackData.size = *loopSizePtr - sample->position;
            sample->callbackData.wrapA = 0;
            sample->callbackData.wrapB = 0;
            if ((d.len = ((int (*)(int, void*))state->callback)(SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND,
                                                                &sample->callbackData)) != 0)
            {
                d.off = sample->position + d.len;
                sample->position = d.off % *loopSizePtr;
            }
            break;
        default:
            break;
        }
    }
    else
    {
        switch (sample->type)
        {
        case SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE:
            sample->callbackData.start =
                (sample->position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) * SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            loopSizePtr = &state->loopSize;
            sample->callbackData.size = *loopSizePtr - sample->position;
            sample->callbackData.wrapA = 0;
            sample->callbackData.wrapB = elapsed;
            if ((d.len = ((int (*)(int, void*))state->callback)(SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND,
                                                                &sample->callbackData)) != 0)
            {
                d.off = sample->position + d.len;
                sample->position = d.off % *loopSizePtr;
            }
            break;
        default:
            break;
        }
    }
}

typedef struct
{
    u8 head[8];

    struct
    {
        u8 b[36];
    } ent[64];
} VSStateLayout;

#define SYNTH_VIRTUAL_SAMPLE_VOICE_STRIDE         0x404
#define SYNTH_VIRTUAL_SAMPLE_VOICE_RELEASE_OFFSET 0x206
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_SCALE        0xa0
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_ROUND        0xfff
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_SHIFT        0x1000

extern u16 synthLoadedGroupCount;

extern u32 hwGetVirtualSampleState(int slot);
extern u32 hwVoiceInStartup(int slot);

/*
 * Periodic virtual-sample tick processor: walks 64 active voices, computes
 * elapsed tick for each, and either advances the envelope (mode 1)
 * or runs sample-completion logic (mode 2 - checks current sample
 * id matches expected and triggers a stop+vacate when threshold
 * elapsed).
 */
void synthUpdateVirtualSamples(void)
{
    u8* state;
    u8* slotMap;
    u32 i;
    u32 currentTick;
    u32 elapsed;
    u8* entry;
    u8 vid;

    if (synthVirtualSampleState.callback != 0)
    {
        state = (u8*)&synthVirtualSampleState;
        slotMap = state;
        for (i = 0; i < SYNTH_VIRTUAL_SAMPLE_MAX_VOICES; i++, slotMap++)
        {
            vid = slotMap[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET];
            if (vid == SYNTH_VIRTUAL_SAMPLE_FREE_SLOT)
            {
                continue;
            }
            if (hwGetVirtualSampleState(i) == 0)
            {
                continue;
            }
            vid = slotMap[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET];
            entry = ((VSStateLayout*)state)->ent[vid].b;

            currentTick = hwChangeStudio(i);
            if (entry[VIRTUAL_SAMPLE_TYPE_OFFSET] == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE)
            {
                elapsed =
                    (currentTick / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) * SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES;
            }
            else
            {
                elapsed = currentTick;
            }

            switch (entry[VIRTUAL_SAMPLE_MODE_OFFSET])
            {
            case SYNTH_VIRTUAL_SAMPLE_MODE_ACTIVE:
                synthAdvanceVirtualSampleEntry(entry, elapsed);
                break;
            case SYNTH_VIRTUAL_SAMPLE_MODE_DONE_WAIT:
            {
                u32 sampleId = hwGetVirtualSampleID(entry[VIRTUAL_SAMPLE_VOICE_OFFSET]);
                u32 expected = ((u32) * (u16*)(entry + VIRTUAL_SAMPLE_GENERATION_OFFSET) << 8) |
                               entry[VIRTUAL_SAMPLE_VOICE_OFFSET];

                if (expected == sampleId)
                {
                    u32 prev;

                    synthAdvanceVirtualSampleEntry(entry, elapsed);
                    prev = *(u32*)(entry + VIRTUAL_SAMPLE_LAST_TICK_OFFSET);
                    if (currentTick >= prev)
                    {
                        *(u32*)(entry + VIRTUAL_SAMPLE_REMAINING_OFFSET) -= (currentTick - prev);
                    }
                    else
                    {
                        *(u32*)(entry + VIRTUAL_SAMPLE_REMAINING_OFFSET) -=
                            *(u32*)(state + SYNTH_VIRTUAL_SAMPLE_LOOP_SIZE_OFFSET) - (prev - currentTick);
                    }
                    *(u32*)(entry + VIRTUAL_SAMPLE_LAST_TICK_OFFSET) = currentTick;

                    if ((s32)(u32)((s32)(*(u16*)((u8*)synthVoice +
                                                 entry[VIRTUAL_SAMPLE_VOICE_OFFSET] *
                                                     SYNTH_VIRTUAL_SAMPLE_VOICE_STRIDE +
                                                 SYNTH_VIRTUAL_SAMPLE_VOICE_RELEASE_OFFSET) *
                                             SYNTH_VIRTUAL_SAMPLE_RELEASE_SCALE +
                                         SYNTH_VIRTUAL_SAMPLE_RELEASE_ROUND) /
                                   SYNTH_VIRTUAL_SAMPLE_RELEASE_SHIFT) >
                        (s32) * (u32*)(entry + VIRTUAL_SAMPLE_REMAINING_OFFSET))
                    {
                        if (hwVoiceInStartup(entry[VIRTUAL_SAMPLE_VOICE_OFFSET]) == 0)
                        {
                            hwBreak(entry[VIRTUAL_SAMPLE_VOICE_OFFSET]);
                        }
                        entry[VIRTUAL_SAMPLE_MODE_OFFSET] = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
                        *(u8*)(state + SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET + entry[VIRTUAL_SAMPLE_VOICE_OFFSET]) =
                            SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
                    }
                }
                else
                {
                    entry[VIRTUAL_SAMPLE_MODE_OFFSET] = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
                    *(u8*)(state + SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET + entry[VIRTUAL_SAMPLE_VOICE_OFFSET]) =
                        SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
                }
            }
            break;
            }
        }
    }
}

/*
 * Reset the loaded sound-group table count.
 */
void synthResetLoadedGroupCount(void)
{
    synthLoadedGroupCount = 0;
}
