#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027B038.h"

extern u8 lbl_803CB290[];

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

    if (packed == 0xffffffffU) {
        return;
    }
    state = lbl_803CB290;
    slots = state + 0x908;
    vid = slots[(u8)packed];
    if (vid == 0xff) {
        return;
    }
    entry = state + vid * 0x24;
    if (*(u16 *)(entry + 0x1a) != ((packed >> 8) & 0xffff)) {
        return;
    }
    if (*(u32 *)(state + 0x94c) != 0) {
        ((void (*)(int, void *))(*(u32 *)(state + 0x94c)))(2, entry + 0x18);
    }
    *(u8 *)(entry + 0x8) = 0;
    slots[*(u8 *)(entry + 0xb)] = 0xff;
}

/* synthAdvanceVirtualSampleEntry is the voice-time elapsed-tick updater - large and
 * shared with placeholder_8027B41C; left as a stub here so the
 * caller (also a stub) links. */
void synthAdvanceVirtualSampleEntry(void *entry, u32 elapsed)
{
    (void)entry;
    (void)elapsed;
}
