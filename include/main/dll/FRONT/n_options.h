#ifndef MAIN_DLL_FRONT_N_OPTIONS_H_
#define MAIN_DLL_FRONT_N_OPTIONS_H_

#include "ghidra_import.h"

void THPPlayerDrawCurrentFrame(void *yTexture,void *uTexture,void *vTexture,u32 width,u32 height);
BOOL Movie_SetVolumeFade(int volume,int fadeFrames);
void AttractMovieAudio_Mix(s16 *dst,s16 *src,u32 sampleCount);
void AttractMovieAudio_DmaCallback(void);
void FUN_80118108(void);
void FUN_8011810c(void);
bool FUN_80118164(u32 param_1);
void THPPlayerPostDrawDone(void);
BOOL THPPlayerGetVideoInfo(void *dst);
void fn_80118240(void);
u32 AttractMovie_DrawTextureCallback(u32 param_1,u32 *modelPtr,u32 renderOpIdx);
int ProperTimingForGettingNextFrame(void);

#endif /* MAIN_DLL_FRONT_N_OPTIONS_H_ */
