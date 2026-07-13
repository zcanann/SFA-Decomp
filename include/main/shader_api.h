#ifndef MAIN_SHADER_API_H_
#define MAIN_SHADER_API_H_

#include "global.h"

struct GameObject;

extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

typedef struct MapRomList
{
    u8 pad00[0x24];
    f32 worldX;
    f32 worldZ;
} MapRomList;

STATIC_ASSERT(offsetof(MapRomList, worldX) == 0x24);
STATIC_ASSERT(offsetof(MapRomList, worldZ) == 0x28);

void* fn_80059334(int x, int z);
MapRomList* mapBlockFn_800592e4(void);
void mapTextureOverrideSetValue(int type, u32 key, int value);
int objUpdateOpacity(struct GameObject* obj);

#endif /* MAIN_SHADER_API_H_ */
