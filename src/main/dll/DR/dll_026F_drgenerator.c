/*
 * drgenerator (DLL 0x26F) - a destructible generator/power node. It
 * takes hits until its hit count (hitsRemaining) reaches zero, then
 * explodes, sets its completion game bit (placement completionGameBit)
 * and either extends a nearby timer object or disables itself. It can
 * also be enabled or disabled at runtime from the placement's watch
 * game bit (watchGameBit).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/dll_02B5_timer.h"
#include "main/game_object.h"
#include "main/dll/DR/dll_026F_drgenerator.h"

#define DRGENERATOR_OBJGROUP 0x3
#define TIMER_OBJGROUP       0x4c
#define DRGENERATOR_PARTFX   0x690

int drgenerator_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            ObjTextureRuntimeSlot* t = objFindTexture((GameObject*)obj, 0, 0);
            if (t != 0)
            {
                t->textureId = 0;
            }
        }
    }
    return 0;
}

int drgenerator_getExtraSize(void)
{
    return 0x19c;
}

int drgenerator_getObjectTypeId(void)
{
    return 0x0;
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

void drgenerator_hitDetect(GameObject* obj)
{
    char* state = (obj)->extra;
    int placement = *(int*)&(obj)->anim.placementData;
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
    if (ObjHits_GetPriorityHitWithPosition(obj, &hitObject, 0, &hitVolume, &hitPosX, &hitPosY, &hitPosZ) != 5)
    {
        return;
    }
    state[0x19a] = *(u8*)(state + 0x19a) - hitVolume;
    Obj_SpawnHitLightAndFade(obj, (const Vec3f*)&hitPosX, lbl_803E6B5C);
    ((void (*)(void*, f32))fn_8009A8C8)(obj, lbl_803E6B60);
    if (state[0x19a] > 0)
    {
        return;
    }
    {
        ObjTextureRuntimeSlot* tex = objFindTexture(obj, 0, 0);
        ((void (*)(void*, f32, int, int, int, int, int, int, int))spawnExplosion)(obj, lbl_803E6B64, 1, 1, 1, 1, 0, 1,
                                                                                  0);
        if (tex != 0)
        {
            tex->textureId = 0x100;
        }
    }
    ((BitFlags8*)(state + 0x19b))->b0 = 1;
    mainSetBits(((DrgeneratorPlacement*)placement)->completionGameBit, 1);
    if ((obj)->anim.seqId == 0x716 &&
        (found = (void*)((int (*)(int, void*, void*))ObjGroup_FindNearestObject)(TIMER_OBJGROUP, obj, 0)) != NULL)
    {
        timer_addDuration((GameObject*)found, ((DrgeneratorState*)state)->timerDuration);
    }
    else
    {
        ((void (*)(void*))ObjHits_DisableObject)(obj);
    }
}

void drgenerator_update(GameObject* obj)
{
    char* state = (obj)->extra;
    int placement = *(int*)&(obj)->anim.placementData;
    int n;
    if (((BitFlags8*)(state + 0x19b))->b4 == 0 && mainGetBit(0x9b9) != 0)
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
    if (mainGetBit(((DrgeneratorPlacement*)placement)->watchGameBit) != 0)
    {
        goto enable;
    }
    if ((obj)->anim.seqId != 0x72e)
    {
        (*gObjectTriggerInterface)->runSequence(4, (void*)obj, -1);
    }
    ((BitFlags8*)(state + 0x19b))->b3 = 1;
    ((BitFlags8*)(state + 0x19b))->b0 = 0;
    ObjHits_DisableObject((int)obj);
    return;
enable:
    if (((BitFlags8*)(state + 0x19b))->b3 == 0)
    {
        goto loop;
    }
    if (mainGetBit(((DrgeneratorPlacement*)placement)->watchGameBit) == 0)
    {
        goto loop;
    }
    if ((obj)->anim.seqId != 0x72e)
    {
        (*gObjectTriggerInterface)->runSequence(3, (void*)obj, -1);
    }
    ((BitFlags8*)(state + 0x19b))->b3 = 0;
    ObjHits_EnableObject((int)obj);
    return;
loop:
    if (((BitFlags8*)(state + 0x19b))->b0 == 0)
    {
        return;
    }
    n = 1;
    do
    {
        (*gPartfxInterface)->spawnObject((void*)obj, DRGENERATOR_PARTFX, NULL, 1, -1, NULL);
    } while (n-- != 0);
}

void drgenerator_init(GameObject* obj, char* arg)
{
    char* state = (obj)->extra;
    f32 fv;
    if ((obj)->anim.seqId == 0x72e)
    {
        ObjTextureRuntimeSlot* t;
        (obj)->animEventCallback = drgenerator_SeqFn;
        t = objFindTexture(obj, 0, 0);
        if (t != 0)
        {
            t->textureId = 0x100;
        }
    }
    ((DrgeneratorState*)state)->hitsRemaining = 2;
    ((void (*)(void*))ObjHits_EnableObject)(obj);
    if (mainGetBit(((DrgeneratorPlacement*)arg)->completionGameBit) != 0)
    {
        (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ((void (*)(void*))Obj_RemoveFromUpdateList)(obj);
        ((void (*)(void*))ObjHits_DisableObject)(obj);
    }
    ((void (*)(void*, int))ObjGroup_AddObject)(obj, DRGENERATOR_OBJGROUP);
    *(int*)state = 0;
    ((BitFlags8*)(state + 0x19b))->b3 = 1;
    (obj)->anim.rotX = (s16)((s8)arg[0x18] << 8);
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
    if (mainGetBit(0x9b9) != 0)
    {
        ((BitFlags8*)(state + 0x19b))->b0 = 1;
        ((BitFlags8*)(state + 0x19b))->b4 = 1;
    }
    else
    {
        ((BitFlags8*)(state + 0x19b))->b4 = 0;
    }
    fv = lbl_803E6B6C;
    (obj)->anim.velocityZ = fv;
    (obj)->anim.velocityY = fv;
    (obj)->anim.velocityX = fv;
}

void drgenerator_release(void)
{
}

void drgenerator_initialise(void)
{
}
