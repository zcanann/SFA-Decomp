#ifndef MAIN_AUDIO_ADSR_HANDLE_H_
#define MAIN_AUDIO_ADSR_HANDLE_H_

#include "ghidra_import.h"

int adsrStartRelease(int state, int divisor);
int adsrRelease(int state);
int adsrHandle(int state, s16 *out1, s16 *out2);

#endif /* MAIN_AUDIO_ADSR_HANDLE_H_ */
