/*
 * FireFlyLantern (DLL 0x10B). TU = 0x801871C8..0x80187640.
 */
#include "main/dll/CF/CFcrystal.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/dll/VF/vf_shared.h"

/* object group this object belongs to */
#define FIREFLYLANTERN_OBJGROUP 0xf
extern int gameBitDecrement(int bit);
extern void* getTrickyObject(void);
extern void trickyImpress(u8* obj);
extern f32 lbl_803E3AF0;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int loadObjectAtObject(int* obj, void* setup);
extern f32 lbl_803E3AE8;

int FireFlyLantern_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    FireFlyLanternState* state;
    void* child;
    int i;

    state = ((GameObject*)obj)->extra;
    i = 0;
    while (i < animUpdate->eventCount)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if (state->fireflyCount != 0)
            {
                child = (void*)state->fireflies[state->fireflyCount - 1];
                if (child != 0)
                {
                    (*(void (*)(void*))(*(int*)(*(int*)(*(int*)((u8*)child + 0x68)) + 0x24)))(child);
                }
                --state->fireflyCount;
                --state->remainingCount;
                GameBit_Set(state->gameBit, state->remainingCount);
            }
            break;
        }
        i++;
    }

    ((FireFlyLanternStateFlags*)&state->flags)->finished = 1;
    i = 0;
    while (i < state->fireflyCount)
    {
        child = (void*)state->fireflies[i];
        (*(void (*)(void*, f32, f32, f32))(*(int*)(*(int*)(*(int*)((u8*)child + 0x68)) + 0x28)))(
            child, ((GameObject*)obj)->anim.localPosX, 5.0f + ((GameObject*)obj)->anim.localPosY,
            ((GameObject*)obj)->anim.localPosZ);
        i++;
    }

    return 0;
}

int FireFlyLantern_getExtraSize(void) { return 0x24; }
int FireFlyLantern_getObjectTypeId(void) { return 0x8; }

void FireFlyLantern_free(int obj)
{
    void* tricky = getTrickyObject();
    if (tricky != NULL)
    {
        trickyImpress(tricky);
    }
    ObjGroup_RemoveObject(obj, FIREFLYLANTERN_OBJGROUP);
}

void FireFlyLantern_render(void) { objRenderFn_8003b8f4(lbl_803E3AF0); }

void FireFlyLantern_update(int obj)
{
    int* slot;
    FireFlyLanternState* state;
    FireFlyLanternSpawnSetup* def;
    void* child;
    int i;
    int shouldFree;

    state = ((GameObject*)obj)->extra;
    def = *(FireFlyLanternSpawnSetup**)&((GameObject*)obj)->anim.placementData;
    shouldFree = 0;

    if ((s8)def->field19 == 1)
    {
        if (state->fireflyCount != 0)
        {
            child = (void*)state->fireflies[0];
            if (child != 0)
            {
                (*(void (*)(void*))(*(int*)(*(int*)(*(int*)((u8*)child + 0x68)) + 0x24)))(child);
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

void FireFlyLantern_init(int obj, int def)
{
    void* player;
    u8* childSlot;
    FireFlyLanternState* state;
    int i;
    u32 childCount;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = FireFlyLantern_SeqFn;
    player = (void*)Obj_GetPlayerObject();
    if (((GameObject*)player)->anim.seqId != 0)
    {
        state->gameBit = 0x13d;
    }
    else
    {
        state->gameBit = 0x5d6;
    }

    state->fireflyCount = 0;
    state->remainingCount = GameBit_Get(state->gameBit);

    if ((s8)((FireFlyLanternSpawnSetup*)def)->field19 == 1)
    {
        if (state->remainingCount != 0)
        {
            state->fireflyCount = 1;
            state->fireflies[0] = FireFlyLantern_spawnFireFly((int*)obj);
        }
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        state->fireflyCount = (state->remainingCount < 6) ? state->remainingCount : 6;

        i = 0;
        childSlot = (u8*)state;
        while (i < state->fireflyCount)
        {
            *(int*)childSlot = FireFlyLantern_spawnFireFly((int*)obj);
            childSlot += 4;
            i++;
        }
    }
}

int FireFlyLantern_spawnFireFly(int* obj)
{
    FireFlyLanternSpawnSetup* setup;
    if (Obj_IsLoadingLocked() == 0) return 0;
    setup = (FireFlyLanternSpawnSetup*)Obj_AllocObjectSetup(sizeof(FireFlyLanternSpawnSetup), 1084);
    setup->objectType = 1084;
    setup->setupType = 9;
    setup->field04 = 2;
    setup->field06 = 0xff;
    setup->field05 = 4;
    setup->field07 = 8;
    setup->x = ((GameObject*)obj)->anim.localPosX;
    setup->y = lbl_803E3AE8 + ((GameObject*)obj)->anim.localPosY;
    setup->z = ((GameObject*)obj)->anim.localPosZ;
    setup->field19 = 4;
    setup->field1A = 0x514;
    setup->field1C = 40;
    setup->field18 = 30;
    return loadObjectAtObject(obj, setup);
}
