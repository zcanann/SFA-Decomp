#ifndef MAIN_AUDIO_SYNTH_CHANNEL_SCALE_H_
#define MAIN_AUDIO_SYNTH_CHANNEL_SCALE_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

void fn_8026EC44(void);
void fn_8026F30C(void);
void synthSetStudioChannelScale(int value, u8 bank, u32 key);
int synthGetVoiceSlotChannelScale(McmdVoiceState *state);
void fn_8026F5B8(int state);
int audioFn_8026f630(u32 key, u32 slot, u32 channel, u32 voiceGroup, u32 *outFlags);

#endif /* MAIN_AUDIO_SYNTH_CHANNEL_SCALE_H_ */
