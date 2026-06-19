#ifndef MAIN_DLL_SCENE1C7_H_
#define MAIN_DLL_SCENE1C7_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/dll/SC/SCtotemlogpuz.h"
#include "main/objanim_update.h"

/* Dbsh shrine carve twins converged (flybaddie.c + scene1C7.c censuses,
 * zero width conflicts: flybaddie's latch[8] pad = scene1C7's observed
 * latch(4)+idleSfxTimer(4); scene1C7's pad00 = flybaddie's light).
 * IDENTITY NOTE: DbshShrineObject is this family's view of the engine
 * GameObject record (triggerRadius@0=anim.rotX slot, x/y/z@0xC=localPos,
 * startX/Y/Z@0x18=worldPos, runtime@0xB8=extra, messageFn@0xBC=unkBC,
 * introDelay@0xF4=unkF4); retiring it to GameObject casts is parked as a
 * recipe-#77-class retype. */
typedef struct DbshShrineFlags {
    u8 latchStarted : 1;
    u8 unused1 : 1;
    u8 unused2 : 1;
    u8 unused3 : 1;
    u8 unused4 : 1;
    u8 unused5 : 1;
    u8 unused6 : 1;
    u8 unused7 : 1;
} DbshShrineFlags;

typedef struct DbshShrineRuntime {
    void *light;
    SCGameBitLatchState latch;
    f32 idleSfxTimer;
    s16 resetTimer;
    u8 pad0E[6];
    u8 state;
    DbshShrineFlags flags; /* scene1C7 mask-tests this byte via *(u8 *)& launder */
} DbshShrineRuntime;

typedef struct DbshShrineObject {
    s16 triggerRadius;
    u8 pad02[4];
    s16 flags;
    u8 pad08[4];
    f32 x;
    f32 y;
    f32 z;
    f32 startX;
    f32 startY;
    f32 startZ;
    u8 pad24[0x88];
    s8 mapId;
    u8 padAD[2];
    u8 mapFlags;
    u8 padB0[8];
    DbshShrineRuntime *runtime;
    int (*messageFn)(int obj, u32 unused, ObjAnimUpdateState *animUpdate);
    u8 padC0[0x34];
    s32 introDelay;
} DbshShrineObject;

STATIC_ASSERT(offsetof(DbshShrineRuntime, idleSfxTimer) == 0x8);
STATIC_ASSERT(offsetof(DbshShrineRuntime, state) == 0x14);
STATIC_ASSERT(offsetof(DbshShrineObject, mapId) == 0xAC);
STATIC_ASSERT(offsetof(DbshShrineObject, runtime) == 0xB8);
STATIC_ASSERT(offsetof(DbshShrineObject, introDelay) == 0xF4);

void dbsh_shrine_update(DbshShrineObject *obj);

#endif /* MAIN_DLL_SCENE1C7_H_ */
