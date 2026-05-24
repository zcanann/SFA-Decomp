#include "ghidra_import.h"
#include "main/dll/flybaddie.h"
#include "main/dll/creator1C6.h"

#define DBSH_SHRINE_GB_FIRST_RISE 0x15f
#define DBSH_SHRINE_GB_ACTIVE 0xefa
#define DBSH_SHRINE_GB_INITIALIZED 0xf08
#define DBSH_SHRINE_LATCH_STARTED 0x80

typedef u8 (*MapEventGetAnimFn)(int mapId, int eventId);
typedef void (*MapEventSetAnimFn)(int mapId, int eventId, int value);

typedef struct DbshShrineRuntime {
    void *light;
    u8 latch[8];
    s16 resetTimer;
    u8 pad0E[6];
    u8 state;
    u8 flags;
} DbshShrineRuntime;

typedef struct DbshShrineObject {
    s16 triggerRadius;
    u8 pad02[0xa];
    f32 x;
    f32 y;
    f32 z;
    f32 startX;
    f32 startY;
    f32 startZ;
    u8 pad24[0x88];
    s8 mapId;
    u8 padAD[0xb];
    DbshShrineRuntime *runtime;
    int (*messageFn)(int obj, undefined4 unused, int animEvents);
    u8 padC0[0x34];
    s32 introDelay;
} DbshShrineObject;

extern void ObjMsg_AllocQueue(DbshShrineObject *obj, int capacity);
extern void *objCreateLight(int obj, int lightType);
extern void GameBit_Set(u32 id, u32 value);
extern int *gMapEventInterface;

#define MAP_EVENT_GET_ANIM(mapId, eventId) \
    ((MapEventGetAnimFn)(*(u32 *)(*gMapEventInterface + 0x4c)))((mapId), (eventId))
#define MAP_EVENT_SET_ANIM(mapId, eventId, value) \
    ((MapEventSetAnimFn)(*(u32 *)(*gMapEventInterface + 0x50)))((mapId), (eventId), (value))

/*
 * --INFO--
 *
 * Function: dbsh_shrine_init
 * EN v1.0 Address: 0x801C9544
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801C9604
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dbsh_shrine_init(DbshShrineObject *obj)
{
    DbshShrineRuntime *runtime;

    runtime = obj->runtime;
    obj->messageFn = fn_801C8EBC;
    obj->triggerRadius = 0;
    runtime->state = 0;
    runtime->flags &= ~DBSH_SHRINE_LATCH_STARTED;
    runtime->resetTimer = 0;

    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(DBSH_SHRINE_GB_FIRST_RISE, 0);

    if (MAP_EVENT_GET_ANIM(obj->mapId, 1) == 0) {
        MAP_EVENT_SET_ANIM(obj->mapId, 1, 1);
    }

    obj->startX = obj->x;
    obj->startY = obj->y;
    obj->startZ = obj->z;
    obj->introDelay = 1;

    if (runtime->light == 0) {
        runtime->light = objCreateLight(0, 1);
    }

    GameBit_Set(DBSH_SHRINE_GB_ACTIVE, 1);
    GameBit_Set(DBSH_SHRINE_GB_INITIALIZED, 1);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dbsh_shrine_release
 * EN v1.0 Address: 0x801C9658
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbsh_shrine_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dbsh_shrine_initialise
 * EN v1.0 Address: 0x801C965C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbsh_shrine_initialise(void)
{
}
