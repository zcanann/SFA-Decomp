#ifndef MAIN_DLL_FRONT_DLL_44_H_
#define MAIN_DLL_FRONT_DLL_44_H_

#include "ghidra_import.h"
#include "main/dll/FRONT/attract_movie.h"

int AttractMovie_AssignBuffers(void *movieOrReadBuffer, void *yTextureBuffer,
                               void *uTextureBuffer, void *vTextureBuffer, void *audioBuffer,
                               void *thpWorkBuffer);
void AttractMovie_GetBufferSizes(uint *movieOrReadBufferSize, int *yTextureBufferSize,
                                 int *uTextureBufferSize, int *vTextureBufferSize,
                                 uint *audioBufferSize, int *thpWorkBufferSize);
int AttractMovie_CloseFile(void);

#endif /* MAIN_DLL_FRONT_DLL_44_H_ */
