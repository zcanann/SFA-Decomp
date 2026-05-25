#ifndef MAIN_AUDIO_HW_VOICE_PARAMS_H_
#define MAIN_AUDIO_HW_VOICE_PARAMS_H_

#include "ghidra_import.h"

void hwSetPitch(int slot, u32 value);
void hwSetSRCType(int slot, u32 value);
void hwSetPolyPhaseFilter(int slot, u32 value);
void hwSetITDMode(int slot, u32 value);

#endif /* MAIN_AUDIO_HW_VOICE_PARAMS_H_ */
