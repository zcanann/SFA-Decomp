#ifndef MAIN_AUDIO_MCMD_VOLUME_H_
#define MAIN_AUDIO_MCMD_VOLUME_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

u32 TranslateVolume(u32 value, u16 keyId);
void mcmdScaleVolume(McmdVoiceState *state, McmdCommandArgs *params, s32 volumeStart);

#endif /* MAIN_AUDIO_MCMD_VOLUME_H_ */
