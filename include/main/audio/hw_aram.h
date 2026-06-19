#ifndef MAIN_AUDIO_HW_ARAM_H_
#define MAIN_AUDIO_HW_ARAM_H_

#include "ghidra_import.h"

u32 hwExitStream(u32 value);
void hwGetStreamPlayBuffer(u32 unused, u32 value);
void hwTransAddr(void);
#endif /* MAIN_AUDIO_HW_ARAM_H_ */
