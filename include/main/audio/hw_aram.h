#ifndef MAIN_AUDIO_HW_ARAM_H_
#define MAIN_AUDIO_HW_ARAM_H_

#include "ghidra_import.h"

u32 hwExitStream(u32 value);
void hwInitSampleMem(u32 baseAddr, u32 length);
void hwExitSampleMem(void);
#endif /* MAIN_AUDIO_HW_ARAM_H_ */
