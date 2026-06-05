#ifndef MAIN_AUDIO_MCMD_SETUP_H_
#define MAIN_AUDIO_MCMD_SETUP_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

void mcmdPlayMacro(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdStartSample(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdVibrato(McmdVoiceState *state, McmdCommandArgs *args);
void DoSetPitch(McmdVoiceState *state);
void mcmdSetADSR(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdSetPitchADSR(McmdVoiceState *state, McmdCommandArgs *args);
void voiceConfigureParamRamp(McmdVoiceState *state, McmdCommandArgs *args, u8 idx);

#endif /* MAIN_AUDIO_MCMD_SETUP_H_ */
