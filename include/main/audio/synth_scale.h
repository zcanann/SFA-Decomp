#ifndef MAIN_AUDIO_SYNTH_SCALE_H_
#define MAIN_AUDIO_SYNTH_SCALE_H_

#include "ghidra_import.h"

void synthSetStudioChannelScale(int value, byte studioIndex, uint channelIndex);
int synthGetVoiceSlotChannelScale(int state);

#endif /* MAIN_AUDIO_SYNTH_SCALE_H_ */
