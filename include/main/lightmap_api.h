#ifndef MAIN_LIGHTMAP_API_H_
#define MAIN_LIGHTMAP_API_H_

#include "types.h"
#include "main/map_block.h"
#include "main/lightmap_text_color_api.h"

void* mapGetBlockAtPos(int x, int y, int layer);
void* RomList_GetLoadedPages(void);
MapBlockData* mapGetBlock(int index);
int coordsToMapCell(f32 x, f32 z);
int isInBounds(f32 x, f32 z);
int isWidescreen(void);
int setWidescreen(u8 enabled);
u8 isOvercast(void);
u32 shouldDrawShadows(void);
int shouldDrawClouds(void);
int getDrawDistanceFlag_8005cd48(void);
int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
void mapGetBlockOriginForPos(f32 x, f32 y, f32 z, f32* outX, f32* outZ);
void setPendingMapLoad(int pending);
void drawFn_8005cf8c(int vertexBase, const u8* triList, int triCount);
void doNothing_8005D148(int arg0, int arg1);
void doNothing_8005D14C(int arg0, int arg1);
void titleScreenFn_8005cdd4(int enabled);
void setIsOvercast(int value);

void setStarsHidden(int v);

void* mapGetBlockIdx(int layer);

#endif /* MAIN_LIGHTMAP_API_H_ */
