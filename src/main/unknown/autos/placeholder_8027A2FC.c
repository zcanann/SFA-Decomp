#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027A2FC.h"
#include "main/unknown/autos/placeholder_80279EC0.h"

extern u8 voiceMidiKeySlots[];
extern u8 voiceDirectSlots[];

/*
 * --INFO--
 *
 * Function: voiceUnregister
 * EN v1.0 Address: 0x8027A2B4
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x8027A2FC
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void voiceUnregister(int obj)
{
    u32 voiceId;
    u32 midiSlot;
    u32 midiChannel;
    u8 key;
    u8 *slot;
    u32 baseAddr;

    voiceId = *(u32 *)(obj + SYNTH_VOICE_HANDLE_OFFSET);
    if (voiceId == 0xffffffff) return;
    midiSlot = *(u8 *)(obj + SYNTH_VOICE_MIDI_SLOT_OFFSET);
    if (midiSlot == 0xff) return;
    midiChannel = *(u8 *)(obj + SYNTH_VOICE_MIDI_CHANNEL_OFFSET);
    key = (u8)voiceId;
    if (midiChannel == 0xff) {
        baseAddr = (u32)voiceDirectSlots;
        slot = (u8 *)(baseAddr + key);
        if (*slot != key) return;
        *slot = 0xff;
    } else {
        baseAddr = (u32)voiceMidiKeySlots;
        slot = (u8 *)(baseAddr + (midiChannel << 4) + midiSlot);
        if (key != *slot) return;
        *slot = 0xff;
    }
}
