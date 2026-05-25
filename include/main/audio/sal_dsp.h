#ifndef MAIN_AUDIO_SAL_DSP_H_
#define MAIN_AUDIO_SAL_DSP_H_

#include "ghidra_import.h"

int salInitDsp(u32 flags);
int salStartDsp(void);
void salCtrlDsp(u32 param_1);
u32 salGetStartDelay(void);
void hwInitIrq(void);
void hwEnableIrq(void);
void sndEnd(void);
void sndBegin(void);
void hwIRQEnterCritical(void);
void hwIRQLeaveCritical(void);
void *salMalloc(u32 size);
void salFree(void *ptr);

#endif /* MAIN_AUDIO_SAL_DSP_H_ */
