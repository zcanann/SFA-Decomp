#ifndef MAIN_TEX_DOLPHIN_EXT_H_
#define MAIN_TEX_DOLPHIN_EXT_H_

#include "types.h"

void mapBlockRender_drawDimmedAabbLights(u32 bounds, u32 blockXform, int i);
void mapBlockRender_drawLightmapIndirectPasses(int blockData, u8* shader, int* bitReader, float* viewMtx);
void mapBlockRender_callList(u32 passSelect, u32 visArg, int block, u8* shader, int* stream, float* mtx);

#endif /* MAIN_TEX_DOLPHIN_EXT_H_ */
