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
    if (*(u32 *)(state + 0x94c) == 0) {
        return;
    }

    slotMap = state;
    for (i = 0; i < 0x40; i++, slotMap++) {
        vid = slotMap[0x908];
        if (vid == 0xff) {
            continue;
        }
        if (hwGetVirtualSampleState(i) == 0) {
            continue;
        }
        vid = slotMap[0x908];
        entry = state + (vid * 0x24 + 8);

        currentTick = hwChangeStudio(i);
        if (entry[2] == 5) {
            elapsed = (currentTick / 0xe) * 0xe;
        } else {
            elapsed = currentTick;
        }

        mode = entry[0];
        if (mode == 2) {
            u32 sampleId = hwGetVirtualSampleID(entry[3]);
            u32 expected = (u32)entry[3] | ((u32)*(u16 *)(entry + 0x12) << 8);
            if (expected != sampleId) {
                entry[0] = 0;
                *(u8 *)(state + 0x908 + entry[3]) = 0xff;
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

                val = *(u16 *)(synthVoice + entry[3] * 0x404 + 0x206);
                threshold = (u32)((s32)(val * 0xa0 + 0xfff) / 0x1000);
                if ((s32)threshold > (s32)*(u32 *)(entry + 8)) {
                    if (hwVoiceInStartup(entry[3]) == 0) {
                        hwBreak(entry[3]);
                    }
                    entry[0] = 0;
                    *(u8 *)(state + 0x908 + entry[3]) = 0xff;
                }
            }
        } else if (mode < 2) {
            if (mode >= 1) {
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
