#ifndef MAIN_LIGHTMAP_API_H_
#define MAIN_LIGHTMAP_API_H_

#include "types.h"
#include "main/map_block.h"

void* mapGetBlockAtPos(int x, int y, int layer);
MapBlockData* mapGetBlock(int index);
int coordsToMapCell(f32 x, f32 z);
int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
void mapGetBlockOriginForPos(f32 x, f32 y, f32 z, f32* outX, f32* outZ);
void setPendingMapLoad(int pending);
void doNothing_8005D148(void);
void doNothing_8005D14C(void);

#define doNothing_8005D148Legacy(a, b) ((void (*)(int, int))doNothing_8005D148)((a), (b))
#define doNothing_8005D14CLegacy(a, b) ((void (*)(int, int))doNothing_8005D14C)((a), (b))

#endif /* MAIN_LIGHTMAP_API_H_ */
