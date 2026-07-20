/*
 * dimdismountpoint (DLL 0x1C9) - dismount-point object for Dinosaur Island
 * Mission 2.  Tracks the nearest conveyor object and exposes a signed-distance
 * plane test so the conveyor can determine which side of the dismount point
 * the player is on.
 */
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/DIM/dll_01C9_dimdismountpoint.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/objprint_render_api.h"
#include "main/obj_group.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/object_api.h"
#include "main/object_render.h"

#define DIMDISMOUNT_GAMEBIT_DONE  0x3e3
#define DIMDISMOUNT_GROUP         0x13
#define DIMCONVEYOR_GROUP         0xa

typedef struct DimdismountpointState
{
    f32 planeNX; /* plane normal X */
    f32 planeNY; /* plane normal Y */
    f32 planeNZ; /* plane normal Z */
    f32 planeD;  /* plane distance (dot(N, pos)) */
} DimdismountpointState;


void DIMDismountPoint_func0B(GameObject *obj, int flag)
{
    (*gObjectTriggerInterface)->runSequence((flag ^ 1) + 2, (void*)obj, -1);
}

int DIMDismountPoint_setScale(GameObject *obj)
{
    GameObject* player = Obj_GetPlayerObject();
    DimdismountpointState* state = obj->extra;
    f32 result;
    int side;

    result = state->planeD +
    (state->planeNZ * player->anim.localPosZ +
        (state->planeNX * player->anim.localPosX +
            state->planeNY * player->anim.localPosY));

    if (result >= 0.0f)
    {
        side = 0;
    }
    else
    {
        side = 1;
    }
    (*gObjectTriggerInterface)->runSequence(side, (void*)obj, -1);
    return side;
}

int DIMDismountPoint_getExtraSize(void) { return 0x10; }

int DIMDismountPoint_getObjectTypeId(void) { return 0; }

void DIMDismountPoint_free(int obj) { ObjGroup_RemoveObject(obj, DIMDISMOUNT_GROUP); }

void DIMDismountPoint_render(GameObject *obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible == 0 || (obj)->userData2 != 0)
    {
        if ((obj)->userData2 != 0)
        {
            objRenderFn_80041018(obj);
        }
    }
    else
    {
        objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, 1.0f);
    }
}

void DIMDismountPoint_hitDetect(void)
{
}

void DIMDismountPoint_update(GameObject* obj)
{
    int* nearest;
    f32 dist;

    dist = 500.0f;
    nearest = (int*)ObjGroup_FindNearestObject(DIMCONVEYOR_GROUP, obj, &dist);
    *(u8*)&obj->anim.resetHitboxMode = (u8)(*(u8*)&obj->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
    if (mainGetBit(DIMDISMOUNT_GAMEBIT_DONE) != 0)
    {
        obj->hitVolumeIndex = 1;
        *(u8*)&obj->anim.resetHitboxMode = (u8)(*(u8*)&obj->anim.resetHitboxMode & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    else
    {
        obj->hitVolumeIndex = 0;
        if (nearest != NULL &&
            ((int (*)(int*, int*))(*(int*)(*(int*)*(int**)&((GameObject*)nearest)->anim.dll + 0x20)))(nearest, (int*)obj) !=
            0)
        {
            *(u8*)&obj->anim.resetHitboxMode = (u8)(
                *(u8*)&obj->anim.resetHitboxMode & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
        }
        else
        {
            *(u8*)&obj->anim.resetHitboxMode = (u8)(
                *(u8*)&obj->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED);
        }
    }
    if ((obj->anim.modelInstance->flags & 1) != 0 &&
        obj->anim.hitVolumeTransforms != NULL)
    {
        objRenderFn_80041018(obj);
    }
}

void DIMDismountPoint_init(GameObject* obj, u8* params)
{
    DimdismountpointState* sub;

    ObjGroup_AddObject((u32)obj, DIMDISMOUNT_GROUP);
    obj->anim.rotX = (s16)((s8)params[0x18] << 8);
    sub = obj->extra;
    sub->planeNX = mathSinf(3.1415927f * (f32)(s32) * (s16*)obj / 32768.0f);
    sub->planeNY = 0.0f;
    sub->planeNZ = mathCosf(3.1415927f * (f32)(s32) * (s16*)obj / 32768.0f);
    sub->planeD = -(sub->planeNX * obj->anim.localPosX + sub->planeNY * obj->anim.localPosY +
        sub->planeNZ * obj->anim.localPosZ);
    obj->userData2 = 1;
}

void DIMDismountPoint_release(void)
{
}

void DIMDismountPoint_initialise(void)
{
}

ObjectDescriptor12 gDIMDismountPointObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)DIMDismountPoint_initialise,
    (ObjectDescriptorCallback)DIMDismountPoint_release,
    0,
    (ObjectDescriptorCallback)DIMDismountPoint_init,
    (ObjectDescriptorCallback)DIMDismountPoint_update,
    (ObjectDescriptorCallback)DIMDismountPoint_hitDetect,
    (ObjectDescriptorCallback)DIMDismountPoint_render,
    (ObjectDescriptorCallback)DIMDismountPoint_free,
    (ObjectDescriptorCallback)DIMDismountPoint_getObjectTypeId,
    DIMDismountPoint_getExtraSize,
    (ObjectDescriptorCallback)DIMDismountPoint_setScale,
    (ObjectDescriptorCallback)DIMDismountPoint_func0B,
};

