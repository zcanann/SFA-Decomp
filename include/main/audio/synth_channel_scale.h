#ifndef MAIN_AUDIO_SYNTH_CHANNEL_SCALE_H_
#define MAIN_AUDIO_SYNTH_CHANNEL_SCALE_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

void seqHandle(u32 deltaTime);
void seqInit(void);
void synthSetStudioChannelScale(int value, u8 bank, u8 key);
int synthGetVoiceSlotChannelScale(McmdVoiceState *state);
void synthInitPortamento(McmdVoiceState *state);
u32 audioFn_8026f630(u8 key, u8 slot, u8 channel, u32 voiceGroup, u32 *outFlags);

#endif /* MAIN_AUDIO_SYNTH_CHANNEL_SCALE_H_ */
