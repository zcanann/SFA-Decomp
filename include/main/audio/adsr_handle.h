#ifndef MAIN_AUDIO_ADSR_HANDLE_H_
#define MAIN_AUDIO_ADSR_HANDLE_H_

#include "ghidra_import.h"

int adsrStartRelease(int state, int divisor);
int adsrRelease(int state);
u32 adsrHandle(int state, u16 *out1, u16 *out2);

#endif /* MAIN_AUDIO_ADSR_HANDLE_H_ */
