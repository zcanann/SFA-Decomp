#ifndef MAIN_AUDIO_ADSR_HANDLE_H_
#define MAIN_AUDIO_ADSR_HANDLE_H_

#include "main/audio/adsr.h"

int adsrStartRelease(ADSR_VARS *adsr, u32 divisor);
int adsrRelease(ADSR_VARS *adsr);
u32 adsrHandle(ADSR_VARS *adsr, u16 *out1, u16 *out2);

#endif /* MAIN_AUDIO_ADSR_HANDLE_H_ */
