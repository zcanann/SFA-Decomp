#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8027591C_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8027591C_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

void mcmdPlayMacro(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdStartSample(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdVibrato(McmdVoiceState *state, McmdCommandArgs *args);
void DoSetPitch(McmdVoiceState *state);
void mcmdSetADSR(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdSetPitchADSR(int state, u32 *args);
void voiceConfigureParamRamp(int state, u32 *args, u32 idx);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8027591C_H_ */
