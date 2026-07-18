#ifndef MAIN_AUDIO_SYNTH_VOLUME_H_
#define MAIN_AUDIO_SYNTH_VOLUME_H_

#include "ghidra_import.h"

void synthVolume(u8 volume, u16 timeMs, u8 target, u8 action, u32 handle);
int synthIsFadeOutActive(u8 voiceIdx);
void synthSetMusicVolumeType(u8 voiceIdx, u8 value);
int synthHWMessageHandler(int mode, u32 arg);

#endif /* MAIN_AUDIO_SYNTH_VOLUME_H_ */
