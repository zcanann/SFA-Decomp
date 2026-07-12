#ifndef MAIN_LIGHTMAP_API_H_
#define MAIN_LIGHTMAP_API_H_

#include "types.h"
#include "main/map_block.h"

void* mapGetBlockAtPos(int x, int y, int layer);
MapBlockData* mapGetBlock(int index);
int objPosToMapBlockIdx(f32 x, f32 y, f32 z);

#endif /* MAIN_LIGHTMAP_API_H_ */
