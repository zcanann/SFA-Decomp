#include "ghidra_import.h"

extern u8 synthVirtualSampleState[];
extern u32 aramGetStreamBufferAddress(u8 slot, u32 *outPos);
extern void hwSetVirtualSampleLoopBuffer(int slot, u32 valueA, u32 valueB);
extern u16 hwGetSampleID(int slot);
extern u8 hwGetSampleType(int slot);

#define SYNTH_VIRTUAL_SAMPLE_ENTRY_COUNT_OFFSET 0
#define SYNTH_VIRTUAL_SAMPLE_LOOP_SIZE_OFFSET 4
#define SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET 8
#define SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE 0x24
#define SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET 0x908
#define SYNTH_VIRTUAL_SAMPLE_NEXT_ID_OFFSET 0x948
#define SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET 0x94c
#define SYNTH_VIRTUAL_SAMPLE_MAX_VOICES 64
#define SYNTH_VIRTUAL_SAMPLE_FREE_SLOT 0xff
#define SYNTH_VIRTUAL_SAMPLE_INVALID_ID 0xffffffffU

#define VIRTUAL_SAMPLE_MODE_OFFSET 0
#define VIRTUAL_SAMPLE_TYPE_OFFSET 2
#define VIRTUAL_SAMPLE_VOICE_OFFSET 3
#define VIRTUAL_SAMPLE_POSITION_OFFSET 4
#define VIRTUAL_SAMPLE_CALLBACK_SAMPLE_ID_OFFSET 0x10
#define VIRTUAL_SAMPLE_GENERATION_OFFSET 0x12
#define VIRTUAL_SAMPLE_CALLBACK_DATA_OFFSET 0x10

/*
 * Reset a 64-byte handle table at synthVirtualSampleState+0x908 to all-0xff,
 * along with surrounding metadata.
 *
 * EN v1.1 Address: 0x8027ACB8, size 288b
 */
void synthInitVirtualSampleTable(void)
{
    int i;
    u8 *state = synthVirtualSampleState;

    state[SYNTH_VIRTUAL_SAMPLE_ENTRY_COUNT_OFFSET] = 0;
    for (i = 0; i < SYNTH_VIRTUAL_SAMPLE_MAX_VOICES; i++) {
        state[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET + i] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
    }
    *(u16 *)(state + SYNTH_VIRTUAL_SAMPLE_NEXT_ID_OFFSET) = 0;
    *(u32 *)(state + SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET) = 0;
}

/*
 * synthClaimVirtualSampleSlot - voice-allocate-and-set-loop helper
 * (~488 instructions).
 */
u32 synthClaimVirtualSampleSlot(u8 voice)
{
    u8 entryIndex;
    u8 *entry;
    u8 *scanEntry;
    u8 *state;
    u16 generation;
    u32 sampleId;
    u32 entryOffset;

    state = synthVirtualSampleState;
    entry = state;
    for (entryIndex = 0; entryIndex < state[SYNTH_VIRTUAL_SAMPLE_ENTRY_COUNT_OFFSET];
         entryIndex++) {
        if (entry[SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_MODE_OFFSET] !=
                0 &&
            entry[SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_VOICE_OFFSET] ==
                voice) {
            entry[SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_MODE_OFFSET] = 0;
            state[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET +
                  entry[SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                        VIRTUAL_SAMPLE_VOICE_OFFSET]] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
        }
        entry += SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE;
    }

    entryIndex = 0;
    entry = state;
    while (entryIndex < state[SYNTH_VIRTUAL_SAMPLE_ENTRY_COUNT_OFFSET]) {
        if (entry[SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_MODE_OFFSET] == 0) {
            entryOffset = entryIndex * SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE;
            entry = state + entryOffset;
            entry[SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_MODE_OFFSET] = 1;
            *(u32 *)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                     VIRTUAL_SAMPLE_POSITION_OFFSET) = 0;
            goto claim_slot;
        }
        entry += SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE;
        entryIndex++;
    }

    entryIndex = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
claim_slot:
    state[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET + voice] = entryIndex;
    if (entryIndex == SYNTH_VIRTUAL_SAMPLE_FREE_SLOT) {
        hwSetVirtualSampleLoopBuffer(voice, 0, 0);
    } else {
        entryIndex = state[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET + voice];
        hwSetVirtualSampleLoopBuffer(
            voice, aramGetStreamBufferAddress(entryIndex, 0),
            *(u32 *)(state + SYNTH_VIRTUAL_SAMPLE_LOOP_SIZE_OFFSET));
        sampleId = hwGetSampleID(voice);
        entryOffset = entryIndex * SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE;
        entry = state + entryOffset;
        *(u16 *)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                 VIRTUAL_SAMPLE_CALLBACK_SAMPLE_ID_OFFSET) = sampleId;

        do {
            generation = *(u16 *)(state + SYNTH_VIRTUAL_SAMPLE_NEXT_ID_OFFSET);
            *(u16 *)(state + SYNTH_VIRTUAL_SAMPLE_NEXT_ID_OFFSET) = generation + 1;
            entryIndex = 0;
            scanEntry = state;
            for (; entryIndex < state[SYNTH_VIRTUAL_SAMPLE_ENTRY_COUNT_OFFSET] &&
                   (scanEntry[SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                              VIRTUAL_SAMPLE_MODE_OFFSET] == 0 ||
                    *(u16 *)(scanEntry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                              VIRTUAL_SAMPLE_GENERATION_OFFSET) != generation);
                 entryIndex++) {
                scanEntry += SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE;
            }
        } while (entryIndex != state[SYNTH_VIRTUAL_SAMPLE_ENTRY_COUNT_OFFSET]);

        *(u16 *)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                 VIRTUAL_SAMPLE_GENERATION_OFFSET) = generation;
        entry[SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_TYPE_OFFSET] =
            hwGetSampleType(voice);
        entry[SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET + VIRTUAL_SAMPLE_VOICE_OFFSET] = voice;

        if (*(u32 *)(state + SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET) != 0) {
            ((int (*)(int, void *))(*(u32 *)(state + SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET)))(
                0,
                entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                    VIRTUAL_SAMPLE_CALLBACK_DATA_OFFSET);
            return CONCAT21(*(u16 *)(entry + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET +
                                     VIRTUAL_SAMPLE_GENERATION_OFFSET),
                            voice);
        }
        hwSetVirtualSampleLoopBuffer(voice, 0, 0);
    }
    return SYNTH_VIRTUAL_SAMPLE_INVALID_ID;
}
