/*
 * FireFlyLantern (DLL 0x10B). TU = 0x801871C8..0x80187640.
 */
#include "main/dll/dll_010B_fireflylantern.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/dll/dll_80136a40.h"
#include "main/gamebits.h"
#include "main/gameloop_gamebit_api.h"
#include "main/obj_group.h"
#include "main/object_render.h"

/* object group this object belongs to */
#define FIREFLYLANTERN_OBJGROUP 0xf

/* Firefly object spawned by FireFlyLantern_spawnFireFly. */
#define FIREFLYLANTERN_CHILD_OBJ_FIREFLY 1084

extern f32 lbl_803E3AF0;
extern const f32 lbl_803E3AEC;
extern f32 lbl_803E3AE8;

GameObject* FireFlyLantern_spawnFireFly(GameObject* obj)
{
    FireFlyLanternSpawnSetup* setup;
    if (Obj_IsLoadingLocked() == 0)
        return NULL;
    setup = (FireFlyLanternSpawnSetup*)Obj_AllocObjectSetup(sizeof(FireFlyLanternSpawnSetup),
                                                            FIREFLYLANTERN_CHILD_OBJ_FIREFLY);
    setup->base.objectId = FIREFLYLANTERN_CHILD_OBJ_FIREFLY;
    setup->base.size = 9;
    setup->base.color[0] = 2;
    setup->base.color[2] = 0xff;
    setup->base.color[1] = 4;
    setup->base.color[3] = 8;
    setup->base.posX = obj->anim.localPosX;
    setup->base.posY = lbl_803E3AE8 + obj->anim.localPosY;
    setup->base.posZ = obj->anim.localPosZ;
    setup->spawnMode = 4;
    setup->field1A = 0x514;
    setup->field1C = 40;
    setup->field18 = 30;
    return loadObjectAtObject(obj, &setup->base);
}

int FireFlyLantern_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    FireFlyLanternState* state;
    GameObject* child;
    int i;

    state = obj->extra;
    i = 0;
    while (i < animUpdate->eventCount)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if (state->fireflyCount != 0)
            {
                child = state->fireflies[state->fireflyCount - 1];
                if (child != 0)
                {
                    (*(void (**)(void*))((char*)*child->anim.dll + 0x24))(child);
                }
                --state->fireflyCount;
                --state->remainingCount;
                mainSetBits(state->gameBit, state->remainingCount);
            }
            break;
        }
        i++;
    }

    ((FireFlyLanternStateFlags*)&state->flags)->finished = 1;
    i = 0;
    while (i < state->fireflyCount)
    {
        child = state->fireflies[i];
        (*(void (**)(void*, f32, f32, f32))((char*)*child->anim.dll + 0x28))(
            child, obj->anim.localPosX, lbl_803E3AEC + obj->anim.localPosY, obj->anim.localPosZ);
        i++;
    }

    return 0;
}

int FireFlyLantern_getExtraSize(void)
{
    return 0x24;
}
int FireFlyLantern_getObjectTypeId(void)
{
    return 0x8;
}

void FireFlyLantern_free(GameObject* obj)
{
    void* tricky = getTrickyObject();
    if (tricky != NULL)
    {
        trickyImpress((GameObject*)tricky);
    }
    ObjGroup_RemoveObject((int)obj, FIREFLYLANTERN_OBJGROUP);
}

void FireFlyLantern_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E3AF0);
}

void FireFlyLantern_update(GameObject* obj)
{
    GameObject** slot;
    FireFlyLanternState* state;
    FireFlyLanternSpawnSetup* placement;
    GameObject* child;
    int i;
    int shouldFree;

    state = (obj)->extra;
    placement = (FireFlyLanternSpawnSetup*)obj->anim.placementData;
    shouldFree = 0;

    if ((s8)placement->spawnMode == 1)
    {
        if (state->fireflyCount != 0)
        {
            child = state->fireflies[0];
            if (child != 0)
            {
                (*(void (**)(void*))((char*)*child->anim.dll + 0x24))(child);
            }
            gameBitDecrement(state->gameBit);
        }
        shouldFree = 1;
    }
    else if (((FireFlyLanternStateFlags*)&state->flags)->finished != 0)
    {
        i = 0;
        slot = state->fireflies;
        while (i < state->fireflyCount)
        {
            Obj_FreeObject(*slot);
            slot++;
            i++;
        }
        shouldFree = 1;
    }

    if (shouldFree != 0)
    {
        Obj_FreeObject(obj);
    }
}

void FireFlyLantern_init(GameObject* obj, FireFlyLanternSpawnSetup* placement)
{
    GameObject* player;
    GameObject** childSlot;
    FireFlyLanternState* state;
    int i;
    u32 childCount;

    state = obj->extra;
    obj->animEventCallback = FireFlyLantern_SeqFn;
    player = Obj_GetPlayerObject();
    if (player->anim.seqId != 0)
    {
        state->gameBit = 0x13d;
    }
    else
    {
        state->gameBit = 0x5d6;
    }

    state->fireflyCount = 0;
    state->remainingCount = mainGetBit(state->gameBit);

    if ((s8)placement->spawnMode == 1)
    {
        if (state->remainingCount != 0)
        {
            state->fireflyCount = 1;
            state->fireflies[0] = FireFlyLantern_spawnFireFly(obj);
        }
        obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        state->fireflyCount = (state->remainingCount < 6) ? state->remainingCount : 6;

        i = 0;
        childSlot = state->fireflies;
        while (i < state->fireflyCount)
        {
            *childSlot = FireFlyLantern_spawnFireFly(obj);
            childSlot++;
            i++;
        }
    }
}
