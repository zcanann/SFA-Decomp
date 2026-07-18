/*
 * dimdismountpoint (DLL 0x1C9) — dismount-point object for Dinosaur Island
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
#include "main/object_render_legacy.h"

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
    int* player = (int*)Obj_GetPlayerObject();
    int* state = (obj)->extra;
    f32 result;
    int side;

    result = ((DimdismountpointState*)state)->planeD +
    (((DimdismountpointState*)state)->planeNZ * ((GameObject*)player)->anim.localPosZ +
        (((DimdismountpointState*)state)->planeNX * ((GameObject*)player)->anim.localPosX +
            ((DimdismountpointState*)state)->planeNY * ((GameObject*)player)->anim.localPosY));

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
            objRenderFn_80041018((GameObject*)obj);
        }
    }
    else
    {
        objRenderModelAndHitVolumes((int)obj, p1, p2, p3, p4, 1.0f);
    }
}

void DIMDismountPoint_hitDetect(void)
{
}

void DIMDismountPoint_update(int* obj)
{
    int* nearest;
    f32 dist;

    dist = 500.0f;
    nearest = (int*)ObjGroup_FindNearestObject(DIMCONVEYOR_GROUP, (u32)obj, &dist);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
    if (mainGetBit(DIMDISMOUNT_GAMEBIT_DONE) != 0)
    {
        ((GameObject*)obj)->hitVolumeIndex = 1;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    else
    {
        ((GameObject*)obj)->hitVolumeIndex = 0;
        if (nearest != NULL &&
            ((int (*)(int*, int*))(*(int*)(*(int*)*(int**)&((GameObject*)nearest)->anim.dll + 0x20)))(nearest, obj) !=
            0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED);
        }
    }
    if ((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0 &&
        ((ObjAnimComponent*)obj)->hitVolumeTransforms != NULL)
    {
        objRenderFn_80041018((GameObject*)obj);
    }
}

void DIMDismountPoint_init(u8* obj, u8* params)
{
    f32* sub;

    ObjGroup_AddObject((u32)obj, DIMDISMOUNT_GROUP);
    ((GameObject*)obj)->anim.rotX = (s16)((s8)params[0x18] << 8);
    sub = ((GameObject*)obj)->extra;
    sub[0] = mathSinf(3.1415927f * (f32)(s32) * (s16*)obj / 32768.0f); /* planeNX */
    sub[1] = 0.0f;                                                     /* planeNY */
    sub[2] = mathCosf(3.1415927f * (f32)(s32) * (s16*)obj / 32768.0f); /* planeNZ */
    sub[3] = -(sub[0] * ((GameObject*)obj)->anim.localPosX + sub[1] * ((GameObject*)obj)->anim.localPosY + sub[2] * ((
        GameObject*)obj)->anim.localPosZ); /* planeD */
    ((GameObject*)obj)->userData2 = 1;
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

/* .sdata2 constant pool */
const u32 lbl_803E4928 = 0xFFFFFFFF;
const f32 lbl_803E492C = 1.0f;
const f32 lbl_803E4930 = 15.0f;
const f32 lbl_803E4934 = 1e+01f;
const f32 lbl_803E4938 = 255.0f;
const f32 lbl_803E493C = 25.0f;
const f32 lbl_803E4940 = 8.0f;
const f32 lbl_803E4944 = 0.0f;
const f32 lbl_803E4948 = 176.0f;
const f32 lbl_803E494C = -0.0f;
const f32 lbl_803E4950 = 7.5f;
const f32 lbl_803E4954 = 2.5f;
const f32 lbl_803E4958 = 3.0f;
const f32 lbl_803E495C = 0.09f;
const f32 lbl_803E4960 = 0.0f;
const f32 lbl_803E4964 = 0.0f;
const f32 lbl_803E4968 = 2.1427498f;
const f32 lbl_803E496C = -6.6188688e+22f;
const f32 lbl_803E4970 = 32768.0f;
const f32 lbl_803E4974 = 0.00390625f;
const f32 lbl_803E4978 = 2.3927f;
const f32 lbl_803E497C = 4.5681372e-11f;
const f32 lbl_803E4980 = 7.5f;
const f32 lbl_803E4984 = 0.0f;
const f32 lbl_803E4988 = -1.0f;
const f32 lbl_803E498C = 0.0f;
const f64 lbl_803E4990 = 4503599627370496.0;
const f32 lbl_803E4998 = 0.2f;
const f32 lbl_803E499C = 0.5f;
const f32 lbl_803E49A0 = 0.95f;
const f32 lbl_803E49A4 = 0.1f;
const f32 lbl_803E49A8 = 1e+02f;
const f32 lbl_803E49AC = 0.4f;
const f32 lbl_803E49B0 = 5.0f;
const f32 lbl_803E49B4 = 2e+01f;
const f32 lbl_803E49B8 = 6.0f;
const f32 lbl_803E49BC = 2.0f;
const f32 lbl_803E49C0 = 0.01f;
const f32 lbl_803E49C4 = 65535.0f;
const f32 lbl_803E49C8 = 16384.0f;
const f32 lbl_803E49CC = 1.5f;
const f32 lbl_803E49D0 = 1.0f;
const f32 lbl_803E49D4 = 0.0f;
const f32 lbl_803E49D8 = 0.95f;
const f32 lbl_803E49DC = 0.9f;
const f32 lbl_803E49E0 = 0.025f;
const f32 lbl_803E49E4 = -4.0f;
const f32 lbl_803E49E8 = 1.0f;
const f32 lbl_803E49EC = 82.0f;
const f32 lbl_803E49F0 = -0.1f;
const f32 lbl_803E49F4 = -5.0f;
const f32 lbl_803E49F8 = 0.1f;
const f32 lbl_803E49FC = 8.0f;
