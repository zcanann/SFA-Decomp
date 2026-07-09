#ifndef MAIN_AUDIO_HW_VOICE_PARAMS_H_
#define MAIN_AUDIO_HW_VOICE_PARAMS_H_

#include "ghidra_import.h"

void hwSetPitch(int slot, u32 value);
void hwSetSRCType(u32 slot, u8 value);
void hwSetPolyPhaseFilter(u32 slot, u8 value);
void hwSetITDMode(u32 slot, u8 value);

#endif /* MAIN_AUDIO_HW_VOICE_PARAMS_H_ */
