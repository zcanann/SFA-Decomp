#ifndef MAIN_PI_DOLPHIN_TEXTURE_API_H_
#define MAIN_PI_DOLPHIN_TEXTURE_API_H_

#include "types.h"

void tex0GetFrame(int texId, int unused, int* outA, int* outB, int count, int* frameTable, int queryMode);
void tex1GetFrame(int texId, int unused, int* outA, int* outB, int count, int* frameTable, int queryMode);
void texPreGetMipmap(int texId, int unused, int* outA, int* outB, int count, int* frameTable, int queryMode);
void freeAndNull(void** p);
#endif /* MAIN_PI_DOLPHIN_TEXTURE_API_H_ */
