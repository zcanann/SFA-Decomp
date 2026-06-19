#ifndef MAIN_AUDIO_SYNTH_SCALE_H_
#define MAIN_AUDIO_SYNTH_SCALE_H_

#include "ghidra_import.h"

void synthSetStudioChannelScale(int value, u8 studioIndex, u32 channelIndex);
int synthGetVoiceSlotChannelScale(int state);

#endif /* MAIN_AUDIO_SYNTH_SCALE_H_ */
