#ifndef MAIN_TEX_DOLPHIN_H_
#define MAIN_TEX_DOLPHIN_H_

#include "ghidra_import.h"
#include "main/frustum.h"

struct MapBlockData;

u8 mapBlockBounds_HasCornerPastDepthThreshold(int param_1,float *param_2);
u32
frustumTestAabbWithPlaneOffsets(f32 minX, f32 maxX, f32 minY, f32 maxY, f32 minZ,
            f32 maxZ, f32 *planeOffsets);
u8
mapBlockBounds_ComputeAndTestPlanes(int bounds,struct MapBlockData *block,FrustumPlane *planes,int planeCount,
            f32 *minX,f32 *minY,f32 *minZ,f32 *maxX,f32 *maxY,f32 *maxZ);
void FUN_8005e884(u32 param_1,u32 param_2,int param_3,int param_4,int *param_5,
                 float *param_6);

#endif /* MAIN_TEX_DOLPHIN_H_ */
