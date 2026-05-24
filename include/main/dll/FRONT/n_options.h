#ifndef MAIN_DLL_FRONT_N_OPTIONS_H_
#define MAIN_DLL_FRONT_N_OPTIONS_H_

#include "ghidra_import.h"

undefined4 FUN_80117668(int param_1,int param_2);
void FUN_80117724(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5);
undefined4 Movie_SetVolumeFade(uint volume,int fadeFrames);
void AttractMovieAudio_Mix(undefined2 *dst,short *src,uint sampleCount);
void AttractMovieAudio_DmaCallback(void);
void FUN_80118108(void);
void FUN_8011810c(void);
bool FUN_80118164(uint param_1);
void THPPlayerPostDrawDone(void);
BOOL THPPlayerGetVideoInfo(void *dst);
void fn_80118240(void);
uint AttractMovie_DrawTextureCallback(undefined4 param_1,undefined4 *modelPtr,undefined4 renderOpIdx);
int ProperTimingForGettingNextFrame(void);

#endif /* MAIN_DLL_FRONT_N_OPTIONS_H_ */
