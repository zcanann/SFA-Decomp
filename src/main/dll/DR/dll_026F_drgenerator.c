/*
 * drgenerator (DLL 0x26F) - a destructible generator/power node. It
 * takes hits until its hit count (hitsRemaining) reaches zero, then
 * explodes, sets its completion game bit (placement completionGameBit)
 * and either extends a nearby timer object or disables itself. It can
 * also be enabled or disabled at runtime from the placement's watch
 * game bit (watchGameBit).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#define DRGENERATOR_OBJGROUP 0x3
#define TIMER_OBJGROUP 0x4c

typedef struct DrgeneratorPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 completionGameBit; /* 0x1E: completion game bit set when destroyed */
    s16 watchGameBit;      /* 0x20: game bit toggling the generator enabled state */
    u8 pad22[0x28 - 0x22];
} DrgeneratorPlacement;

STATIC_ASSERT(offsetof(DrgeneratorPlacement, completionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DrgeneratorPlacement, watchGameBit) == 0x20);
STATIC_ASSERT(sizeof(DrgeneratorPlacement) == 0x28);


typedef struct DrgeneratorState
{
    u8 pad0[0x124 - 0x0];
    f32 unk124;
    u8 pad128[0x198 - 0x128];
    s16 timerDuration; /* 0x198: timer duration handed to a linked timer object */
    u8 hitsRemaining;  /* 0x19A: remaining hit count */
    u8 pad19B[0x19C - 0x19B];
} DrgeneratorState;

STATIC_ASSERT(offsetof(DrgeneratorState, timerDuration) == 0x198);
STATIC_ASSERT(offsetof(DrgeneratorState, hitsRemaining) == 0x19A);
STATIC_ASSERT(sizeof(DrgeneratorState) == 0x19C);


int drgenerator_getExtraSize(void) { return 0x19c; }

int drgenerator_getObjectTypeId(void) { return 0x0; }

void drgenerator_initialise(void)
{
}

void drgenerator_release(void)
{
}

void drgenerator_free(int obj)
{
    ObjGroup_RemoveObject(obj, DRGENERATOR_OBJGROUP);
}

void drgenerator_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E6B58);
    }
}

int drgenerator_eventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            ObjTextureRuntimeSlot* t = objFindTexture((void*)obj, 0, 0);
            if (t != 0)
            {
                t->textureId = 0;
            }
        }
    }
    return 0;
}

void drgenerator_init(int obj, char* arg)
{
    char* state = ((GameObject*)obj)->extra;
    f32 fv;
    if (((GameObject*)obj)->anim.seqId == 0x72e)
    {
        ObjTextureRuntimeSlot* t;
        ((GameObject*)obj)->animEventCallback = drgenerator_eventCallback;
        t = objFindTexture((void*)obj, 0, 0);
        if (t != 0)
        {
            t->textureId = 0x100;
        }
    }
    ((DrgeneratorState*)state)->hitsRemaining = 2;
    ObjHits_EnableObject(obj);
    if (GameBit_Get(((DrgeneratorPlacement*)arg)->completionGameBit) != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        Obj_RemoveFromUpdateList(obj);
        ObjHits_DisableObject(obj);
    }
    ObjGroup_AddObject(obj, DRGENERATOR_OBJGROUP);
    *(int*)state = 0;
    ((BitFlags8*)(state + 0x19b))->b3 = 1;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)arg[0x18] << 8);
    {
        int duration = *(s16*)(arg + 0x1a);
        switch (duration)
        {
        case 0:
            duration = 0x14;
            break;
        }
        ((DrgeneratorState*)state)->timerDuration = duration;
    }
    ((DrgeneratorState*)state)->timerDuration = ((DrgeneratorState*)state)->timerDuration * 0x3c;
    ((DrgeneratorState*)state)->unk124 = lbl_803E6B68;
    if (GameBit_Get(0x9b9) != 0)
    {
        ((BitFlags8*)(state + 0x19b))->b0 = 1;
        ((BitFlags8*)(state + 0x19b))->b4 = 1;
    }
    else
    {
        ((BitFlags8*)(state + 0x19b))->b4 = 0;
    }
    fv = lbl_803E6B6C;
    ((GameObject*)obj)->anim.velocityZ = fv;
    ((GameObject*)obj)->anim.velocityY = fv;
    ((GameObject*)obj)->anim.velocityX = fv;
}

void drgenerator_hitDetect(int obj)
{
    char* state = ((GameObject*)obj)->extra;
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    f32 hitPosZ;
    f32 hitPosY;
    f32 hitPosX;
    u32 hitVolume;
    int hitObject;
    void* found;
    if (((BitFlags8*)(state + 0x19b))->b0 || ((BitFlags8*)(state + 0x19b))->b3)
    {
        return;
    }
    if (ObjHits_GetPriorityHitWithPosition(obj, &hitObject, 0, &hitVolume, &hitPosX, &hitPosY,
                                           &hitPosZ) != 5)
    {
        return;
    }
    state[0x19a] = *(u8*)(state + 0x19a) - hitVolume;
    Obj_SpawnHitLightAndFade(obj, &hitPosX, lbl_803E6B5C);
    fn_8009A8C8(obj, lbl_803E6B60);
    if (state[0x19a] > 0)
    {
        return;
    }
    {
        ObjTextureRuntimeSlot* tex = objFindTexture((void*)obj, 0, 0);
        spawnExplosion(obj, lbl_803E6B64, 1, 1, 1, 1, 0, 1, 0);
        if (tex != 0)
        {
            tex->textureId = 0x100;
        }
    }
    ((BitFlags8*)(state + 0x19b))->b0 = 1;
    GameBit_Set(((DrgeneratorPlacement*)placement)->completionGameBit, 1);
    if (((GameObject*)obj)->anim.seqId == 0x716 &&
        (found = (void*)ObjGroup_FindNearestObject(TIMER_OBJGROUP, obj, 0)) != NULL)
    {
        timer_addDuration((int)found, ((DrgeneratorState*)state)->timerDuration);
    }
    else
    {
        ObjHits_DisableObject(obj);
    }
}

void drgenerator_update(int obj)
{
    char* state = ((GameObject*)obj)->extra;
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    int n;
    if (((BitFlags8*)(state + 0x19b))->b4 == 0 && GameBit_Get(0x9b9) != 0)
    {
        ((BitFlags8*)(state + 0x19b))->b4 = 1;
    }
    if (((BitFlags8*)(state + 0x19b))->b4 != 0)
    {
        goto loop;
    }
    if (((BitFlags8*)(state + 0x19b))->b3 != 0)
    {
        goto enable;
    }
    if (GameBit_Get(((DrgeneratorPlacement*)placement)->watchGameBit) != 0)
    {
        goto enable;
    }
    if (((GameObject*)obj)->anim.seqId != 0x72e)
    {
        (*gObjectTriggerInterface)->runSequence(4, (void*)obj, -1);
    }
    ((BitFlags8*)(state + 0x19b))->b3 = 1;
    ((BitFlags8*)(state + 0x19b))->b0 = 0;
    ObjHits_DisableObject(obj);
    return;
enable:
    if (((BitFlags8*)(state + 0x19b))->b3 == 0)
    {
        goto loop;
    }
    if (GameBit_Get(((DrgeneratorPlacement*)placement)->watchGameBit) == 0)
    {
        goto loop;
    }
    if (((GameObject*)obj)->anim.seqId != 0x72e)
    {
        (*gObjectTriggerInterface)->runSequence(3, (void*)obj, -1);
    }
    ((BitFlags8*)(state + 0x19b))->b3 = 0;
    ObjHits_EnableObject(obj);
    return;
loop:
    if (((BitFlags8*)(state + 0x19b))->b0 == 0)
    {
        return;
    }
    n = 1;
    do
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x690, NULL, 1, -1, NULL);
    }
    while (n-- != 0);
}
