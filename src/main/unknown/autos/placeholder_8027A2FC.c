#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027A2FC.h"
#include "main/unknown/autos/placeholder_80279EC0.h"

extern u8 voiceMidiKeySlots[][SYNTH_VOICE_MIDI_KEY_COUNT];
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
    SynthVoiceState *voice;
    u32 voiceId;
    u32 midiSlot;
    u32 midiChannel;
    u8 *slot;

    voice = (SynthVoiceState *)obj;
    voiceId = voice->handle;
    if (voiceId == SYNTH_INVALID_VOICE) return;
    midiSlot = voice->midiSlot;
    if (midiSlot == SYNTH_INVALID_VOICE_U8) return;
    midiChannel = voice->midiChannel;
    voiceId = (u8)voiceId;
    if (midiChannel == SYNTH_INVALID_VOICE_U8) {
        slot = &voiceDirectSlots[voiceId];
        if (*slot != voiceId) return;
        *slot = SYNTH_INVALID_VOICE_U8;
    } else {
        slot = &voiceMidiKeySlots[midiChannel][midiSlot];
        if (voiceId != *slot) return;
        *slot = SYNTH_INVALID_VOICE_U8;
    }
}
