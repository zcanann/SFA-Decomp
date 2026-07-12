#ifndef MAIN_GAMEPLAY_RUNTIME_H_
#define MAIN_GAMEPLAY_RUNTIME_H_

#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/maketex.h"
#include "main/render.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "global.h"

/* MAPINFO.bin per-record map type (curMapType / getCurMapType(), shader.c). */
typedef enum MapType
{
    MAPTYPE_NORMAL        = 0, /* normal outdoor map */
    MAPTYPE_SUBMAP        = 1, /* normal submap (dungeon/indoor) */
    MAPTYPE_UNLOAD_UNUSED = 2, /* unused: unloads all objects immediately on load */
    MAPTYPE_SUBMAP_UNUSED = 3, /* unused: same as MAPTYPE_UNLOAD_UNUSED; only frontend2 has this */
    MAPTYPE_NO_HUD        = 4, /* hides PDA HUD; title screen + Arwing maps; no player object spawned */
} MapType;

/* One 0x20-byte MAPINFO.bin (fileId 0x1f) record, fetched by mapId via getTabEntry. */
typedef struct MapInfoRecord
{
    u8 unk00[0x1c];
    s8 mapType; /* +0x1c: MapType */
    u8 unk1d;
    s16 unk1e; /* +0x1e */
} MapInfoRecord;

void objRenderFn_80041018(int obj);
void loadUiDll(int index);
void defragMemory(int mode);
int loadMapAndParent(int mapId);
int lockLevel(s32 val, int idx);
int mapUnload(int mapDir, int flags);
int mapGetDirIdx(int mapId);
void warpToMap(int idx, s8 transType);
void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
int unlockLevel(s32 val, int idx, int flag);
void envFxActFn_800887f8(u8 value);
void setMotionBlur(int mode, f32 amount);
void streamFn_8000a380(int mask, int mode, int time);
void *getTrickyObject(void);

#endif /* MAIN_GAMEPLAY_RUNTIME_H_ */
