#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8028479C_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8028479C_H_

#include "ghidra_import.h"

void salCallback(u32 p1, u32 p2, u32 p3, int p4, u32 p5, u32 p6);
void dspInitCallback(void);
void dspResumeCallback(void);
int salInitAi(void *userCallback, u32 unused, u32 *outSampleCount);
void salStartAi(void);
int salExitAi(void);
int salAiGetDest(void);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8028479C_H_ */
