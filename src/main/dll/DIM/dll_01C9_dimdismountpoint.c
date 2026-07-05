/*
 * dimdismountpoint (DLL 0x1C9) — dismount-point object for Dinosaur Island
 * Mission 2.  Tracks the nearest conveyor object and exposes a signed-distance
 * plane test so the conveyor can determine which side of the dismount point
 * the player is on.
 */
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"

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

extern f32 lbl_803E4910;
extern f32 lbl_803E4908;
extern f32 lbl_803E4914;
extern f32 lbl_803E4918;
extern float mathSinf(float x);
extern float mathCosf(float x);
extern f32 lbl_803E490C;

void dimdismountpoint_hitDetect(void)
{
}

void dimdismountpoint_release(void)
{
}

void dimdismountpoint_initialise(void)
{
}

void dimdismountpoint_update(int* obj)
{
    int* nearest;
    f32 d;

    d = lbl_803E4910;
    nearest = (int*)ObjGroup_FindNearestObject(DIMCONVEYOR_GROUP, (u32)obj, &d);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
    if (GameBit_Get(DIMDISMOUNT_GAMEBIT_DONE) != 0)
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
        objRenderFn_80041018((int)obj);
    }
}

void dimdismountpoint_init(u8* obj, u8* params)
{
    f32* sub;

    ObjGroup_AddObject((u32)obj, DIMDISMOUNT_GROUP);
    ((GameObject*)obj)->anim.rotX = (s16)((s8)params[0x18] << 8);
    sub = ((GameObject*)obj)->extra;
    sub[0] = mathSinf(lbl_803E4914 * (f32)(s32) * (s16*)obj / lbl_803E4918); /* planeNX */
    sub[1] = lbl_803E4908;                                                     /* planeNY */
    sub[2] = mathCosf(lbl_803E4914 * (f32)(s32) * (s16*)obj / lbl_803E4918); /* planeNZ */
    sub[3] = -(sub[0] * ((GameObject*)obj)->anim.localPosX + sub[1] * ((GameObject*)obj)->anim.localPosY + sub[2] * ((
        GameObject*)obj)->anim.localPosZ); /* planeD */
    ((GameObject*)obj)->unkF8 = 1;
}

int dimdismountpoint_getExtraSize(void) { return 0x10; }

void dimdismountpoint_free(int x) { ObjGroup_RemoveObject(x, DIMDISMOUNT_GROUP); }


int dimdismountpoint_getObjectTypeId(void) { return 0; }

void dimdismountpoint_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible == 0 || ((GameObject*)obj)->unkF8 != 0)
    {
        if (((GameObject*)obj)->unkF8 != 0)
        {
            objRenderFn_80041018(obj);
        }
    }
    else
    {
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E490C);
    }
}

void dimdismountpoint_func11(int obj, int flag)
{
    (*gObjectTriggerInterface)->runSequence((flag ^ 1) + 2, (void*)obj, -1);
}

int dimdismountpoint_setScale(int obj)
{
    int* player = (int*)Obj_GetPlayerObject();
    int* state = ((GameObject*)obj)->extra;
    f32 result;
    int side;

    result = ((DimdismountpointState*)state)->planeD +
    (((DimdismountpointState*)state)->planeNZ * ((GameObject*)player)->anim.localPosZ +
        (((DimdismountpointState*)state)->planeNX * ((GameObject*)player)->anim.localPosX +
            ((DimdismountpointState*)state)->planeNY * ((GameObject*)player)->anim.localPosY));

    if (result >= lbl_803E4908)
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
