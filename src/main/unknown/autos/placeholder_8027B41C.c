#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027B41C.h"

extern u32 synthAdvanceVirtualSampleEntry(void *entry, u32 tick);
extern u32 hwChangeStudio(int slot);
extern u32 hwGetVirtualSampleState(int slot);
extern u16 hwGetVirtualSampleID(int slot);
extern u32 hwVoiceInStartup(int slot);
extern void hwBreak(int slot);

extern u8 lbl_803CB290[];
extern u8 *lbl_803DE268;
extern u16 lbl_803DE308;

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
    int i;
    u32 currentTick;
    u32 elapsed;
    u8 *entry;

    state = lbl_803CB290;
    if (*(u32 *)(state + 0x94c) == 0) {
        return;
    }

    for (i = 0; i < 0x40; i++) {
        u8 vid = *(u8 *)(state + 0x908 + i);
        if (vid == 0xff) {
            continue;
        }
        if (hwGetVirtualSampleState(i) == 0) {
            continue;
        }
        vid = *(u8 *)(state + 0x908 + i);
        entry = state + (vid * 0x24 + 8);

        currentTick = hwChangeStudio(i);
        if (entry[2] == 5) {
            elapsed = (currentTick / 7) * 0xe;
        } else {
            elapsed = currentTick;
        }

        if (entry[0] == 2) {
            u16 sampleId = hwGetVirtualSampleID(entry[3]);
            u32 expected = (u32)entry[3] | ((u32)*(u16 *)(entry + 0x12) << 8);
            if ((expected & 0xffffff) != sampleId) {
                entry[0] = 0;
                *(u8 *)(state + 0x908 + entry[3]) = 0xff;
            } else {
                u32 prev;
                u32 threshold;
                u16 val;
                synthAdvanceVirtualSampleEntry(entry, elapsed);
                prev = *(u32 *)(entry + 0xc);
                if (currentTick < prev) {
                    u32 delta = *(u32 *)(state + 4) - (prev - currentTick);
                    *(u32 *)(entry + 8) -= delta;
                } else {
                    *(u32 *)(entry + 8) -= (currentTick - prev);
                }
                *(u32 *)(entry + 0xc) = currentTick;

                val = *(u16 *)(lbl_803DE268 + entry[3] * 0x404 + 0x206);
                threshold = (u32)((s32)(val * 0xa0 + 0xfff) >> 12);
                if ((s32)threshold > (s32)*(u32 *)(entry + 8)) {
                    if (hwVoiceInStartup(entry[3]) == 0) {
                        hwBreak(entry[3]);
                    }
                    entry[0] = 0;
                    *(u8 *)(state + 0x908 + entry[3]) = 0xff;
                }
            }
        } else if (entry[0] == 1) {
            synthAdvanceVirtualSampleEntry(entry, elapsed);
        }
    }
}

/*
 * EN v1.1 Address: 0x8027B420
 * EN v1.1 Size: 12b
 */
void synthResetVirtualSampleCounter(void)
{
    lbl_803DE308 = 0;
}
