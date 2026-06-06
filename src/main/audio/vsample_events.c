#include "main/audio/synth_virtual_sample.h"
#include "main/audio/vsample_events.h"

extern u8 synthVirtualSampleState[];

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
    SynthVirtualSampleState *state;
    u8 *slots;
    u8 vid;
    u8 *entry;
    u32 entryOffset;
    u32 generation;

    state = (SynthVirtualSampleState *)synthVirtualSampleState;
    slots = state->voiceMap;
    if (packed == SYNTH_VIRTUAL_SAMPLE_INVALID_ID) {
        return;
    }
    vid = slots[(u8)packed];
    if (vid == SYNTH_VIRTUAL_SAMPLE_FREE_SLOT) {
        return;
    }
    entryOffset = vid * SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE;
    generation = (packed >> 8) & 0xffff;
    /* raw sum keeps target's lhzx (const folds onto the index) */
    if (*(u16 *)((u8 *)state + entryOffset + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                 VIRTUAL_SAMPLE_GENERATION_OFFSET) != generation) {
        return;
    }
    if (state->callback != NULL) {
        state->callback(SYNTH_VIRTUAL_SAMPLE_DONE_CALLBACK_KIND,
                        &state->entries[vid].callbackData);
    }
    entry = (u8 *)state + entryOffset;
    *(u8 *)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_MODE_OFFSET) =
        SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
    slots[*(u8 *)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                  VIRTUAL_SAMPLE_VOICE_OFFSET)] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

void synthAdvanceVirtualSampleEntry(void *entry, u32 elapsed)
{
    SynthVirtualSampleState *state;
    SynthVirtualSampleEntry *sample;
    u32 *loopSizePtr;
    u32 position;
    u32 loopSize;
    u32 advanced;

    state = (SynthVirtualSampleState *)synthVirtualSampleState;
    sample = entry;
    position = sample->position;
    if (position == elapsed) {
        return;
    }

    if (position < elapsed) {
        if ((int)sample->type == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE) {
            sample->callbackData.start =
                (position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
                SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            sample->callbackData.size = elapsed - sample->position;
            sample->callbackData.wrapA = 0;
            sample->callbackData.wrapB = 0;
            advanced = ((int (*)(int, void *))state->callback)(
                SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND,
                &sample->callbackData);
            if (advanced != 0U) {
                position = sample->position + advanced;
                loopSize = state->loopSize;
                sample->position = position - (position / loopSize) * loopSize;
            }
        } else {
            return;
        }
    } else if (elapsed == 0) {
        if ((int)sample->type == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE) {
            sample->callbackData.start =
                (position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
                SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            loopSizePtr = &state->loopSize;
            sample->callbackData.size = *loopSizePtr - sample->position;
            sample->callbackData.wrapA = 0;
            sample->callbackData.wrapB = 0;
            advanced = ((int (*)(int, void *))state->callback)(
                SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND,
                &sample->callbackData);
            if (advanced != 0U) {
                position = sample->position + advanced;
                loopSize = *loopSizePtr;
                sample->position = position - (position / loopSize) * loopSize;
            }
        } else {
            return;
        }
    } else if ((int)sample->type == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE) {
        sample->callbackData.start =
            (position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
            SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
        loopSizePtr = &state->loopSize;
        sample->callbackData.size = *loopSizePtr - sample->position;
        sample->callbackData.wrapA = 0;
        sample->callbackData.wrapB = elapsed;
        advanced = ((int (*)(int, void *))state->callback)(
            SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND,
            &sample->callbackData);
        if (advanced != 0U) {
            position = sample->position + advanced;
            loopSize = *loopSizePtr;
            sample->position = position - (position / loopSize) * loopSize;
        }
    } else {
        return;
    }
}
