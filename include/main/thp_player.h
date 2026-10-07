#ifndef MAIN_THP_PLAYER_H_
#define MAIN_THP_PLAYER_H_

#include "main/dll/FRONT/attract_movie.h"
#include "dolphin/ai.h"

BOOL AttractMovieAudio_Init(int audioMode);
void AttractMovieAudio_Shutdown(void);
BOOL movieLoad(const char* fileName, BOOL onMemory);
int AttractMovie_CloseFile(void);
void AttractMovie_GetBufferSizes(u32* movieOrReadBufferSize, int* yTextureBufferSize, int* uTextureBufferSize,
                                 int* vTextureBufferSize, u32* audioBufferSize, int* thpWorkBufferSize);
int AttractMovie_AssignBuffers(void* movieOrReadBuffer, void* yTextureBuffer, void* uTextureBuffer,
                               void* vTextureBuffer, void* audioBuffer, void* thpWorkBuffer);
void PrepareReady(int ready);
BOOL prepareAttractMode(u32 movieIndex, s32 playFlags);
BOOL THPPlayerPlay(void);
void THPPlayerStop(void);
int ProperTimingForGettingNextFrame(void);
BOOL AttractMovie_DrawTextureCallback(int unused, u32* modelPtr, u32 renderOpIdx);
void AttractMovie_AddVideoTevStages(void);
BOOL THPPlayerGetVideoInfo(void* dst);
void THPPlayerPostDrawDone(void);
void AttractMovieAudio_DmaCallback(void);
BOOL Movie_SetVolumeFade(int volume, int fadeFrames);
void THPPlayerDrawCurrentFrame(void* yBuf, void* uBuf, void* vBuf, u32 width, u32 height);

#endif /* MAIN_THP_PLAYER_H_ */
