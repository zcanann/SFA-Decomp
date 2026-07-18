#ifndef MAIN_PI_DOLPHIN_TEXTURE_API_H_
#define MAIN_PI_DOLPHIN_TEXTURE_API_H_

#include "types.h"

void tex0GetFrame(int texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode);
void tex1GetFrame(u32 texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode);
void texPreGetMipmap(u32 texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode);
void freeAndNull(void** p);
void trickyVoxAllocFn_8004b5d4(int* out);
void* fn_8004B118(int* p);
int fn_8004B148(int* p);

#endif /* MAIN_PI_DOLPHIN_TEXTURE_API_H_ */
