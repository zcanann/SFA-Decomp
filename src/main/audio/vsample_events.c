#include "main/audio/synth_virtual_sample.h"

#pragma exceptions on

u8 synthVirtualSampleState[0x950];

/*
 * Sample-completion handler: if the packed (slotIdx, sampleId)
 * still matches the active sample, fire the global "done" callback
 * with kind=2, then clear the entry's mode and free the slot back to
 * the index pool.
 *
 * EN v1.0 Address: 0x8027ADC0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027AFC0
 * EN v1.1 Size: 168b
 */
void synthHandleVirtualSampleDone(u32 packed)
{
    SynthVirtualSampleState* state;
    u8* entry;
    u32 entryOffset;
    u8* slots;
    u8 vid;
    u32 generation;

    state = (SynthVirtualSampleState*)synthVirtualSampleState;
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
        state->callback(SYNTH_VIRTUAL_SAMPLE_DONE_CALLBACK_KIND,
                        &state->entries[vid].callbackData);
    }
    entry = (u8*)state + entryOffset;
    *(u8*)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_MODE_OFFSET) =
        SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
    slots[*(u8*)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
        VIRTUAL_SAMPLE_VOICE_OFFSET)] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
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

    state = (SynthVirtualSampleState*)synthVirtualSampleState;
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
                (sample->position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
                SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            sample->callbackData.size = elapsed - sample->position;
            sample->callbackData.wrapA = 0;
            sample->callbackData.wrapB = 0;
            if ((d.len = ((int (*)(int, void*))state->callback)(
                SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND,
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
                (sample->position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
                SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            loopSizePtr = &state->loopSize;
            sample->callbackData.size = *loopSizePtr - sample->position;
            sample->callbackData.wrapA = 0;
            sample->callbackData.wrapB = 0;
            if ((d.len = ((int (*)(int, void*))state->callback)(
                SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND,
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
                (sample->position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
                SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            loopSizePtr = &state->loopSize;
            sample->callbackData.size = *loopSizePtr - sample->position;
            sample->callbackData.wrapA = 0;
            sample->callbackData.wrapB = elapsed;
            if ((d.len = ((int (*)(int, void*))state->callback)(
                SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND,
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
