#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80279EC0_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80279EC0_H_

#include "ghidra_import.h"

#define SYNTH_INVALID_VOICE 0xFFFFFFFFU
#define SYNTH_INVALID_VOICE_U8 0xFF
#define SYNTH_VOICE_STRIDE 0x404
#define SYNTH_VOICE_MIDI_CHANNEL_COUNT 8
#define SYNTH_VOICE_MIDI_KEY_COUNT 16
#define SYNTH_VOICE_DIRECT_SLOT_COUNT 64
#define SYNTH_VOICE_REGISTRATION_CLEAR_BLOCKS 4
#define SYNTH_VOICE_REGISTRATION_CLEAR_STRIDE 32
#define SYNTH_VOICE_REGISTRATION_FREE SYNTH_INVALID_VOICE_U8

#define SYNTH_VOICE_NEXT_HANDLE_OFFSET 0xEC
#define SYNTH_VOICE_HANDLE_OFFSET 0xF4
#define SYNTH_VOICE_ACTIVE_HANDLE_OFFSET 0x34
#define SYNTH_VOICE_PRIORITY_TICK_OFFSET 0x110
#define SYNTH_VOICE_STATE_FLAGS_OFFSET 0x118
#define SYNTH_VOICE_CALLBACK_ACTIVE_OFFSET 0x11C
#define SYNTH_VOICE_MIDI_SLOT_OFFSET 0x121
#define SYNTH_VOICE_MIDI_CHANNEL_OFFSET 0x122

typedef struct VoiceIdSlot {
    u8 prev;
    u8 next;
    u16 active;
} VoiceIdSlot;

typedef struct SynthVoiceState {
    u8 pad00[0x34];
    u32 activeHandle;
    u8 pad38[0xec - 0x38];
    u32 nextHandle;
    u8 padf0[0xf4 - 0xf0];
    u32 handle;
    u8 padf8[0x110 - 0xf8];
    u32 priorityTick;
    u32 dirtyFlags;
    u32 stateFlags;
    u8 callbackActive;
    u8 pad11d[0x121 - 0x11d];
    u8 midiSlot;
    u8 midiChannel;
} SynthVoiceState;

void voiceInitPriorityTables(void);
void voiceBreakAndFree(u32 voice);
void voiceKill(u32 voice);
int voiceKillById(u32 id);
int voiceIsRegistered(int state);
void voiceRegister(int state);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80279EC0_H_ */
