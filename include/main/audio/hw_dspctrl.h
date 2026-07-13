#ifndef MAIN_AUDIO_HW_DSPCTRL_H_
#define MAIN_AUDIO_HW_DSPCTRL_H_

#include "ghidra_import.h"

void salBuildCommandList(s16 *dest, u32 nsDelay);
void salHandleAuxProcessing(void);

#endif /* MAIN_AUDIO_HW_DSPCTRL_H_ */
