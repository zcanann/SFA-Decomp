#ifndef MAIN_TEX_DOLPHIN_EXT_H_
#define MAIN_TEX_DOLPHIN_EXT_H_

#include "types.h"

struct MapBlockData;
struct MapShader;

void mapBlockRender_drawDimmedAabbLights(u32 bounds, u32 blockXform, int i);
void mapBlockRender_drawLightmapIndirectPasses(int blockData, u8* shader, int* bitReader, float (*viewMtx)[4]);
struct MapShader* mapBlockRender_setShader(u8 doSetup, struct MapBlockData* blockData, int* bitReader);
void mapBlockRender_callList(u32 passSelect, u32 visArg, struct MapBlockData* block, struct MapShader* shader,
                             int* stream, float* mtx);

#endif /* MAIN_TEX_DOLPHIN_EXT_H_ */
