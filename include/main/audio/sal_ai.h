#ifndef MAIN_AUDIO_SAL_AI_H_
#define MAIN_AUDIO_SAL_AI_H_

#include "ghidra_import.h"

typedef void (*SalAiCallback)(void);

extern SalAiCallback salAiCallback;

void salCallback(u32 p1, u32 p2, u32 p3, int p4, u32 p5, u32 p6);
void dspInitCallback(void* task);
void dspResumeCallback(void* task);
int salInitAi(SalAiCallback userCallback, u32 unused, u32* outSampleCount);
void salStartAi(void);
int salExitAi(void);
int salAiGetDest(void);

#endif /* MAIN_AUDIO_SAL_AI_H_ */
