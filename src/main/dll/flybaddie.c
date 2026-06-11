#include "main/mapEvent.h"
#include "main/dll/flybaddie.h"
#include "main/dll/creator1C6.h"

#define DBSH_SHRINE_GB_FIRST_RISE 0x15f
#define DBSH_SHRINE_GB_ACTIVE 0xefa
#define DBSH_SHRINE_GB_INITIALIZED 0xf08

extern void ObjMsg_AllocQueue(DbshShrineObject* obj, int capacity);
extern void* objCreateLight(int obj, int lightType);
extern void GameBit_Set(u32 id, u32 value);
extern MapEventInterface** gMapEventInterface;

#define MAP_EVENT_GET_ANIM(mapId, eventId) \
    (*gMapEventInterface)->getAnimEvent((mapId), (eventId))
#define MAP_EVENT_SET_ANIM(mapId, eventId, value) \
    (*gMapEventInterface)->setAnimEvent((mapId), (eventId), (value))

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
void dbsh_shrine_init(DbshShrineObject* obj)
{
    DbshShrineRuntime* runtime;

    runtime = obj->runtime;
    obj->messageFn = fn_801C8EBC;
    obj->triggerRadius = 0;
    runtime->state = 0;
    runtime->flags.latchStarted = 0;
    runtime->resetTimer = 0;

    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(DBSH_SHRINE_GB_FIRST_RISE, 0);

    if (MAP_EVENT_GET_ANIM(obj->mapId, 1) == 0)
    {
        MAP_EVENT_SET_ANIM(obj->mapId, 1, 1);
    }

    obj->startX = obj->x;
    obj->startY = obj->y;
    obj->startZ = obj->z;
    obj->introDelay = 1;

    if (runtime->light == 0)
    {
        runtime->light = objCreateLight(0, 1);
    }

    GameBit_Set(DBSH_SHRINE_GB_ACTIVE, 1);
    GameBit_Set(DBSH_SHRINE_GB_INITIALIZED, 1);
}

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
