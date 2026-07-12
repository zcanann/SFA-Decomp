#ifndef MAIN_SHADER_API_H_
#define MAIN_SHADER_API_H_

#include "global.h"

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

#endif /* MAIN_SHADER_API_H_ */
