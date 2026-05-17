#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027B41C.h"

extern void synthAdvanceVirtualSampleEntry(void *entry, u32 tick);
extern u32 hwChangeStudio(int slot);
extern u32 hwGetVirtualSampleState(int slot);
extern u32 hwGetVirtualSampleID(int slot);
extern u32 hwVoiceInStartup(int slot);
extern void hwBreak(int slot);

extern u8 synthVirtualSampleState[];
extern u8 *synthVoice;
extern u16 synthLoadedGroupCount;

#define SYNTH_VIRTUAL_SAMPLE_VOICE_STRIDE 0x404
#define SYNTH_VIRTUAL_SAMPLE_VOICE_RELEASE_OFFSET 0x206
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_SCALE 0xa0
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_ROUND 0xfff
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_SHIFT 0x1000

/*
 * Periodic virtual-sample tick processor: walks 64 active voices, computes
 * elapsed tick for each, and either advances the envelope (mode 1)
 * or runs sample-completion logic (mode 2 - checks current sample
 * id matches expected and triggers a stop+vacate when threshold
 * elapsed).
 *
 * EN v1.0 Address: 0x8027B25C
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027B41C
 * EN v1.1 Size: 452b
 */
void synthUpdateVirtualSamples(void)
{
    u8 *state;
    u8 *slotMap;
    u32 i;
    u32 currentTick;
    u32 elapsed;
    u8 *entry;
    u8 vid;
    int mode;

    state = synthVirtualSampleState;
    if (*(u32 *)(state + SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET) == 0) {
        return;
    }

    slotMap = state;
    for (i = 0; i < SYNTH_VIRTUAL_SAMPLE_MAX_VOICES; i++, slotMap++) {
        vid = slotMap[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET];
        if (vid == SYNTH_VIRTUAL_SAMPLE_FREE_SLOT) {
            continue;
        }
        if (hwGetVirtualSampleState(i) == 0) {
            continue;
        }
        vid = slotMap[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET];
        entry = state + (vid * SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE + SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET);

        currentTick = hwChangeStudio(i);
        if (entry[VIRTUAL_SAMPLE_TYPE_OFFSET] == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE) {
            elapsed = (currentTick / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
                      SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES;
        } else {
            elapsed = currentTick;
        }

        mode = entry[VIRTUAL_SAMPLE_MODE_OFFSET];
        if (mode == SYNTH_VIRTUAL_SAMPLE_MODE_DONE_WAIT) {
            u32 sampleId = hwGetVirtualSampleID(entry[VIRTUAL_SAMPLE_VOICE_OFFSET]);
            u32 expected = (u32)entry[VIRTUAL_SAMPLE_VOICE_OFFSET] |
                           ((u32)*(u16 *)(entry + VIRTUAL_SAMPLE_GENERATION_OFFSET) << 8);
            if (expected != sampleId) {
                entry[VIRTUAL_SAMPLE_MODE_OFFSET] = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
                *(u8 *)(state + SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET +
                        entry[VIRTUAL_SAMPLE_VOICE_OFFSET]) = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
            } else {
                u32 prev;
                u32 threshold;
                u16 val;
                synthAdvanceVirtualSampleEntry(entry, elapsed);
                prev = *(u32 *)(entry + 0xc);
                if (currentTick >= prev) {
                    *(u32 *)(entry + 8) -= (currentTick - prev);
                } else {
                    u32 delta = *(u32 *)(state + 4) - (prev - currentTick);
                    *(u32 *)(entry + 8) -= delta;
                }
                *(u32 *)(entry + 0xc) = currentTick;

                val = *(u16 *)(synthVoice +
                               entry[VIRTUAL_SAMPLE_VOICE_OFFSET] * SYNTH_VIRTUAL_SAMPLE_VOICE_STRIDE +
                               SYNTH_VIRTUAL_SAMPLE_VOICE_RELEASE_OFFSET);
                threshold = (u32)((s32)(val * SYNTH_VIRTUAL_SAMPLE_RELEASE_SCALE +
                                        SYNTH_VIRTUAL_SAMPLE_RELEASE_ROUND) /
                                  SYNTH_VIRTUAL_SAMPLE_RELEASE_SHIFT);
                if ((s32)threshold > (s32)*(u32 *)(entry + 8)) {
                    if (hwVoiceInStartup(entry[VIRTUAL_SAMPLE_VOICE_OFFSET]) == 0) {
                        hwBreak(entry[VIRTUAL_SAMPLE_VOICE_OFFSET]);
                    }
                    entry[VIRTUAL_SAMPLE_MODE_OFFSET] = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
                    *(u8 *)(state + SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET +
                            entry[VIRTUAL_SAMPLE_VOICE_OFFSET]) = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
                }
            }
        } else if (mode < SYNTH_VIRTUAL_SAMPLE_MODE_DONE_WAIT) {
            if (mode >= SYNTH_VIRTUAL_SAMPLE_MODE_ACTIVE) {
                synthAdvanceVirtualSampleEntry(entry, elapsed);
            }
        }
    }
}

/*
 * Reset the loaded sound-group table count.
 *
 * EN v1.1 Address: 0x8027B420
 * EN v1.1 Size: 12b
 */
void synthResetLoadedGroupCount(void)
{
    synthLoadedGroupCount = 0;
}
