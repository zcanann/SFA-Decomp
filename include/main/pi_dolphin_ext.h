#ifndef MAIN_PI_DOLPHIN_EXT_H_
#define MAIN_PI_DOLPHIN_EXT_H_

#include "dolphin/types.h"

void loadModelsBin(int fileOffset, int* animCount, int* headerSize, int* amapFlag, int* dataLen, int id);
void* fileLoad(int id, int heap);
void videoInit(void* rmode, int arg);
void textureFn_8004ff20(void* asset, f32* mtx, void* out, int p4);
#endif /* MAIN_PI_DOLPHIN_EXT_H_ */
