#ifndef MUSYX_VOICE_MANAGE_H_
#define MUSYX_VOICE_MANAGE_H_

#include "types.h"

#define SYNTH_INVALID_VOICE 0xFFFFFFFFU
#define SYNTH_INVALID_VOICE_U8 0xFF
#define SYNTH_VOICE_STRIDE 0x404
#define SYNTH_VOICE_MIDI_CHANNEL_COUNT 8
#define SYNTH_VOICE_MIDI_KEY_COUNT 16
#define SYNTH_VOICE_DIRECT_SLOT_COUNT 64
#define SYNTH_VOICE_REGISTRATION_CLEAR_BLOCKS 4
#define SYNTH_VOICE_REGISTRATION_CLEAR_STRIDE 32
#define SYNTH_VOICE_REGISTRATION_FREE SYNTH_INVALID_VOICE_U8

typedef struct McmdVoiceState McmdVoiceState;

extern u16 voicePrioSortedRoot;
extern u8 voiceMusicRunning;
extern u8 voiceFxRunning;
extern u8 voiceFreeListTail;
extern u8 voiceFreeListRoot;

void synthInitAllocationAids(void);
void voiceUnblock(u32 voice);
void voiceKill(u32 voice);
int voiceKillSound(u32 id);
u32 voiceIsLastStarted(McmdVoiceState *voice);
void voiceSetLastStarted(McmdVoiceState* state);

#endif /* MUSYX_VOICE_MANAGE_H_ */
