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
u32 isOvercast(void);
int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
void mapGetBlockOriginForPos(f32 x, f32 y, f32 z, f32* outX, f32* outZ);
void setPendingMapLoad(int pending);
void drawFn_8005cf8c(int vertexBase, u8* triList, int triCount);
void doNothing_8005D148(void);
void doNothing_8005D14C(void);
void titleScreenFn_8005cdd4(int enabled);
void setIsOvercast(int value);

#define isOvercastByteLegacy() ((u8 (*)(void))isOvercast)()

#define doNothing_8005D148Legacy(a, b) ((void (*)(int, int))doNothing_8005D148)((a), (b))
#define doNothing_8005D14CLegacy(a, b) ((void (*)(int, int))doNothing_8005D14C)((a), (b))

#endif /* MAIN_LIGHTMAP_API_H_ */
