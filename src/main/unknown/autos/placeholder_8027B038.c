#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027B038.h"

extern u8 synthVirtualSampleState[];

#define SYNTH_VIRTUAL_SAMPLE_LOOP_SIZE_OFFSET 4
#define SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET 0x94c
#define SYNTH_VIRTUAL_SAMPLE_FREE_SLOT 0xff
#define SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE 5
#define SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES 14
#define SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES 8

#define VIRTUAL_SAMPLE_MODE_OFFSET 0
#define VIRTUAL_SAMPLE_TYPE_OFFSET 2
#define VIRTUAL_SAMPLE_VOICE_OFFSET 3
#define VIRTUAL_SAMPLE_POSITION_OFFSET 4
#define VIRTUAL_SAMPLE_CALLBACK_DATA_OFFSET 0x10
#define VIRTUAL_SAMPLE_CALLBACK_START_OFFSET 0x14
#define VIRTUAL_SAMPLE_CALLBACK_SIZE_OFFSET 0x18
#define VIRTUAL_SAMPLE_CALLBACK_WRAP_A_OFFSET 0x1c
#define VIRTUAL_SAMPLE_CALLBACK_WRAP_B_OFFSET 0x20
#define VIRTUAL_SAMPLE_GENERATION_OFFSET 0x12

/*
 * Sample-completion handler: if the packed (slotIdx, sampleId)
 * still matches the active sample, fire the global "done" callback
 * (state->[0x94c]) with mode=2, then clear the entry's mode and free
 * the slot back to the index pool.
 *
 * EN v1.0 Address: 0x8027ADC0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027AFC0
 * EN v1.1 Size: 168b
 */
void synthHandleVirtualSampleDone(u32 packed)
{
    u8 *state;
    u8 *slots;
    u8 vid;
    u8 *entry;
    u32 entryOffset;
    u32 generation;

    state = synthVirtualSampleState;
    slots = state + 0x908;
    if (packed == 0xffffffffU) {
        return;
    }
    vid = slots[(u8)packed];
    if (vid == SYNTH_VIRTUAL_SAMPLE_FREE_SLOT) {
        return;
    }
    entryOffset = vid * 0x24;
    generation = (packed >> 8) & 0xffff;
    if (*(u16 *)(state + entryOffset + 0x1a) != generation) {
        return;
    }
    if (*(u32 *)(state + SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET) != 0) {
        ((void (*)(int, void *))(*(u32 *)(state + SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET)))(
            2, state + entryOffset + 0x18);
    }
    entry = state + entryOffset;
    *(u8 *)(entry + 0x8) = 0;
    slots[*(u8 *)(entry + 0xb)] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

void synthAdvanceVirtualSampleEntry(void *entry, u32 elapsed)
{
    u8 *state;
    u8 *sample;
    u32 *loopSizePtr;
    u32 position;
    u32 loopSize;
    u32 advanced;

    state = synthVirtualSampleState;
    sample = entry;
    position = *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET);
    if (position == elapsed) {
        return;
    }

    if (position < elapsed) {
        if ((int)sample[VIRTUAL_SAMPLE_TYPE_OFFSET] == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE) {
            *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_START_OFFSET) =
                (position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
                SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_SIZE_OFFSET) =
                elapsed - *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET);
            *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_WRAP_A_OFFSET) = 0;
            *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_WRAP_B_OFFSET) = 0;
            advanced = ((int (*)(int, void *))(*(u32 *)(state +
                                                        SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET)))(
                1, sample + VIRTUAL_SAMPLE_CALLBACK_DATA_OFFSET);
            if (advanced != 0U) {
                position = *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET) + advanced;
                loopSize = *(u32 *)(state + SYNTH_VIRTUAL_SAMPLE_LOOP_SIZE_OFFSET);
                *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET) =
                    position - (position / loopSize) * loopSize;
            }
        } else {
            return;
        }
    } else if (elapsed == 0) {
        if ((int)sample[VIRTUAL_SAMPLE_TYPE_OFFSET] == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE) {
            *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_START_OFFSET) =
                (position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
                SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            loopSizePtr = (u32 *)(state + SYNTH_VIRTUAL_SAMPLE_LOOP_SIZE_OFFSET);
            *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_SIZE_OFFSET) =
                *loopSizePtr - *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET);
            *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_WRAP_A_OFFSET) = 0;
            *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_WRAP_B_OFFSET) = 0;
            advanced = ((int (*)(int, void *))(*(u32 *)(state +
                                                        SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET)))(
                1, sample + VIRTUAL_SAMPLE_CALLBACK_DATA_OFFSET);
            if (advanced != 0U) {
                position = *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET) + advanced;
                loopSize = *loopSizePtr;
                *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET) =
                    position - (position / loopSize) * loopSize;
            }
        } else {
            return;
        }
    } else if ((int)sample[VIRTUAL_SAMPLE_TYPE_OFFSET] == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE) {
        *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_START_OFFSET) =
            (position / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
            SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
        loopSizePtr = (u32 *)(state + SYNTH_VIRTUAL_SAMPLE_LOOP_SIZE_OFFSET);
        *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_SIZE_OFFSET) =
            *loopSizePtr - *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET);
        *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_WRAP_A_OFFSET) = 0;
        *(u32 *)(sample + VIRTUAL_SAMPLE_CALLBACK_WRAP_B_OFFSET) = elapsed;
        advanced = ((int (*)(int, void *))(*(u32 *)(state +
                                                    SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET)))(
            1, sample + VIRTUAL_SAMPLE_CALLBACK_DATA_OFFSET);
        if (advanced != 0U) {
            position = *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET) + advanced;
            loopSize = *loopSizePtr;
            *(u32 *)(sample + VIRTUAL_SAMPLE_POSITION_OFFSET) =
                position - (position / loopSize) * loopSize;
        }
    } else {
        return;
    }
}
