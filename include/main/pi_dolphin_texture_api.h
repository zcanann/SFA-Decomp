#ifndef MAIN_PI_DOLPHIN_TEXTURE_API_H_
#define MAIN_PI_DOLPHIN_TEXTURE_API_H_

#include "types.h"

void tex0GetFrame(int texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode);
void tex1GetFrame(u32 texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode);
void texPreGetMipmap(u32 texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode);
void freeAndNull(void** p);
#endif /* MAIN_PI_DOLPHIN_TEXTURE_API_H_ */
