#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8028479C_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8028479C_H_

#include "ghidra_import.h"

void FUN_80284670(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,undefined4 param_6);
void salCallback(u32 p1, u32 p2, u32 p3, int p4, u32 p5, u32 p6);
void dspInitCallback(void);
void dspResumeCallback(void);
int salInitAi(void *userCallback, u32 unused, u32 *outSampleCount);
void salStartAi(void);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8028479C_H_ */
