#ifndef MAIN_TEX_DOLPHIN_H_
#define MAIN_TEX_DOLPHIN_H_

#include "ghidra_import.h"
#include "main/frustum.h"

struct MapBlockData;
struct MapShader;

u8 mapBlockBounds_HasCornerPastDepthThreshold(int param_1,float *param_2);
u32
frustumTestAabbWithPlaneOffsets(f32 minX, f32 maxX, f32 minY, f32 maxY, f32 minZ,
            f32 maxZ, f32 *planeOffsets);
u8
mapBlockBounds_ComputeAndTestPlanes(int bounds,struct MapBlockData *block,FrustumPlane *planes,int planeCount,
            f32 *minX,f32 *minY,f32 *minZ,f32 *maxX,f32 *maxY,f32 *maxZ);
void FUN_8005e884(u32 param_1,u32 param_2,int param_3,int param_4,int *param_5,
                 float *param_6);
void mapBlockRender_drawDimmedAabbLights(u32 bounds, u32 blockXform, int index);
void mapBlockRender_drawLightmapIndirectPasses(struct MapBlockData* blockData, struct MapShader* shader,
                                               int* bitReader, float (*viewMtx)[4]);
struct MapShader* mapBlockRender_setLightmapShader(struct MapBlockData* blockData, int* bitReader);
#ifdef TEX_SETSHADER_U8
struct MapShader* mapBlockRender_setShader(u8 doSetup, struct MapBlockData* blockData, int* bitReader);
#else
struct MapShader* mapBlockRender_setShader(int doSetup, struct MapBlockData* blockData, int* bitReader);
#endif
void mapBlockRender_callList(u32 passSelect, u32 visArg, struct MapBlockData* block, struct MapShader* shader,
                             int* stream, float* mtx);

#endif /* MAIN_TEX_DOLPHIN_H_ */
