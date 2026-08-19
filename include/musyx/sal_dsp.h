#ifndef MUSYX_SAL_DSP_H_
#define MUSYX_SAL_DSP_H_

#include "types.h"

extern u16 dspCmdFirstSize;
extern u16* dspCmdList;
extern u16 hwIrqLevel;
extern u32 oldState;

int salInitDsp(u32 flags);
int salStartDsp(void);
void salCtrlDsp(s16* dest);
u32 salGetStartDelay(void);
void hwInitIrq(void);
void hwEnableIrq(void);
void sndEnd(void);
void sndBegin(void);
void hwIRQEnterCritical(void);
void hwIRQLeaveCritical(void);
void *salMalloc(u32 size);
void salFree(void* ptr);

#endif /* MUSYX_SAL_DSP_H_ */
