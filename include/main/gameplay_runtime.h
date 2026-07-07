#ifndef MAIN_GAMEPLAY_RUNTIME_H_
#define MAIN_GAMEPLAY_RUNTIME_H_

#include "main/audio/sfx.h"
#include "main/gamebits.h"
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

void objRenderFn_80041018(int obj);
void loadUiDll(int index);
void defragMemory(int mode);
int loadMapAndParent(int mapId);
int lockLevel(int mapDir, int locked);
int mapUnload(int mapDir, int flags);
int mapGetDirIdx(int mapId);
void warpToMap(int mapId, int transition);
void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
void unlockLevel(int mapId, int flags, int unlocked);
void envFxActFn_800887f8(u8 value);
void getEnvfxActImmediately(void *obj, void *target, int effectId, int flags);
void setMotionBlur(int mode, f32 amount);
void streamFn_8000a380(int mask, int mode, int time);
void storeZeroToFloatParam(void *timer);
void s16toFloat(void *timer, int duration);
int timerCountDown(void *timer);
int randomGetRange(int min, int max);
void mm_free(void *ptr);
void *Obj_GetPlayerObject(void);
void *getTrickyObject(void);

#endif /* MAIN_GAMEPLAY_RUNTIME_H_ */
