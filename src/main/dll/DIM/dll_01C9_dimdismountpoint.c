#include "main/dll/DIM/DIM2conveyor.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"

typedef struct DimdismountpointState
{
    f32 unk0;
    f32 unk4;
    f32 unk8;
    f32 unkC;
} DimdismountpointState;

extern uint GameBit_Get(int eventId);

extern void objRenderFn_80041018(int obj);
extern f32 lbl_803E4910;
extern f32 lbl_803E4908;
extern f32 lbl_803E4914;
extern f32 lbl_803E4918;
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E490C;
extern int Obj_GetPlayerObject(void);

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
    extern uint GameBit_Get(int eventId);
    int* nearest;
    f32 d;

    d = lbl_803E4910;
    nearest = (int*)ObjGroup_FindNearestObject(0xa, (u32)obj, &d);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
    if (GameBit_Get(0x3e3) != 0)
    {
        ((GameObject*)obj)->unkE4 = 1;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x10);
    }
    else
    {
        ((GameObject*)obj)->unkE4 = 0;
        if (nearest != NULL &&
            ((int (*)(int*, int*))(*(int*)(*(int*)*(int**)&((GameObject*)nearest)->anim.dll + 0x20)))(nearest, obj) !=
            0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x10);
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x10);
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

    ObjGroup_AddObject((u32)obj, 0x13);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    sub = ((GameObject*)obj)->extra;
    sub[0] = mathSinf(lbl_803E4914 * (f32)(s32) * (s16*)obj / lbl_803E4918);
    sub[1] = lbl_803E4908;
    sub[2] = mathCosf(lbl_803E4914 * (f32)(s32) * (s16*)obj / lbl_803E4918);
    sub[3] = -(sub[0] * ((GameObject*)obj)->anim.localPosX + sub[1] * ((GameObject*)obj)->anim.localPosY + sub[2] * ((
        GameObject*)obj)->anim.localPosZ);
    ((GameObject*)obj)->unkF8 = 1;
}

int dimdismountpoint_getExtraSize(void) { return 0x10; }

void dimdismountpoint_free(int x) { ObjGroup_RemoveObject(x, 0x13); }

void dimbridgecogmai_release(void);

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
        objRenderFn_8003b8f4(lbl_803E490C);
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

    result = ((DimdismountpointState*)state)->unkC +
    (((DimdismountpointState*)state)->unk8 * ((GameObject*)player)->anim.localPosZ +
        (((DimdismountpointState*)state)->unk0 * ((GameObject*)player)->anim.localPosX +
            ((DimdismountpointState*)state)->unk4 * ((GameObject*)player)->anim.localPosY));

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
