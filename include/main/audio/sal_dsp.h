#ifndef MAIN_AUDIO_SAL_DSP_H_
#define MAIN_AUDIO_SAL_DSP_H_

#include "ghidra_import.h"

extern u16 dspCmdFirstSize;
extern u16* dspCmdList;
extern u16 hwIrqLevel;
extern u32 oldState;

int salInitDsp(u32 flags);
int salStartDsp(void);
void salCtrlDsp(u32 dest);
u32 salGetStartDelay(void);
void hwInitIrq(void);
void hwEnableIrq(void);
void sndEnd(void);
void sndBegin(void);
void hwIRQEnterCritical(void);
void hwIRQLeaveCritical(void);
void *salMalloc(u32 size);

#endif /* MAIN_AUDIO_SAL_DSP_H_ */
