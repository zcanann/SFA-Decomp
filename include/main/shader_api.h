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

/* MAPINFO.bin per-record map type (curMapType / getCurMapType()). */
typedef enum MapType
{
    MAPTYPE_NORMAL        = 0, /* normal outdoor map */
    MAPTYPE_SUBMAP        = 1, /* normal submap (dungeon/indoor) */
    MAPTYPE_UNLOAD_UNUSED = 2, /* unused: unloads all objects immediately on load */
    MAPTYPE_SUBMAP_UNUSED = 3, /* unused: same as MAPTYPE_UNLOAD_UNUSED; only frontend2 has this */
    MAPTYPE_NO_HUD        = 4, /* hides PDA HUD; title screen + Arwing maps; no player object spawned */
} MapType;

void* fn_80059334(int x, int z);
MapRomList* mapBlockFn_800592e4(void);
void mapBlockFn_80059c2c(u8* outFlags);
s32 getCurMapType(void);
void mapTextureOverrideSetValue(int type, u32 key, int value);
int objUpdateOpacity(struct GameObject* obj);
void playerUpdateFn_8005649c(void);
void doPendingMapLoads(void);
void mapReloadWithFadeout(void);
void initMaps(void);
void unloadMap(void);
void beginLoadingMap(void);
void goToNextMapLayer(void);
void goToPrevMapLayer(void);
void playerVecFn_8005a9b0(void);
s32 getCurMapLayer(void);

#endif /* MAIN_SHADER_API_H_ */
