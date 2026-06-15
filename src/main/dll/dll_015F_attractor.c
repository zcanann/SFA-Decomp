#include "main/dll/DR/dll_015A_explodable.h"
#include "main/dll/drexplodable_types.h"
#include "main/obj_placement.h"
#include "main/objlib.h"

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

/* segment pragma-stack balance (re-split): */

#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/mapEvent.h"
#include "main/dll/IM/IMicicle.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern undefined8 FUN_80017698();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E43D0;
extern void* Obj_GetPlayerObject(void);
extern f32 lbl_803E43C0;
extern int atan2i(int y, int x);

void FUN_801a4520(int param_1)
{
    int iVar1;

    if (((GameObject*)param_1)->unkF4 == 0)
    {
        iVar1 = *(int*)&((GameObject*)param_1)->anim.placementData;
        if ((*(short*)(iVar1 + 0x1c) != 0) && (**(byte**)&((GameObject*)param_1)->extra >> 5 != 0))
        {
            (*gObjectTriggerInterface)->preempt(param_1, *(s16*)(iVar1 + 0x1c));
        }
        iVar1 = (int)*(char*)(iVar1 + 0x1e);
        if (iVar1 != -1)
        {
            (*gObjectTriggerInterface)->runSequence(iVar1, (void*)param_1, -1);
        }
        ((GameObject*)param_1)->unkF4 = 1;
    }
    return;
}

void FUN_801a45cc(short* param_1, int param_2)
{
}

void cflevelcontrol_free(int param_1);

undefined4
FUN_801a4810(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             undefined4 param_9, undefined4 param_10, ObjAnimUpdateState* animUpdate)
{
    undefined4 handle;
    int i;
    undefined8 obj;

    for (i = 0; i < (int)(uint)animUpdate->eventCount; i = i + 1)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            FUN_80017698(0xdcb, 1);
            obj = FUN_80017698(0x4a3, 0);
            FUN_80041ff8(obj, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x2b);
            FUN_80042b9c(0, 0, 1);
            handle = FUN_80044404(0x2b);
            FUN_80042bec(handle, 0);
        }
    }
    return 0;
}

void cfforcefield_release(void);

void attractor_hitDetect(void)
{
}

void attractor_update(void)
{
}

void attractor_release(void)
{
}

void attractor_initialise(void)
{
}

void cfmagicwall_free(void);

int attractor_getExtraSize(void) { return 0x0; }
int attractor_getObjectTypeId(void) { return 0x0; }
int cfmagicwall_getExtraSize(void);

void attractor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43D0);
}

void cfmagicwall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void attractor_free(int x) { ObjGroup_RemoveObject(x, 0x1e); }

u32 exploded_getObjectTypeId(ExplodedObject* obj);

int attractor_setScale(int* obj)
{
    int* p = (int*)((int**)obj)[0x4c / 4];
    if ((s8) * ((u8*)p + 0x19) != 0)
    {
        return *(s16*)((char*)p + 0x1a);
    }
    return 0;
}

void attractor_init(s16* obj, void* data)
{
    ObjGroup_AddObject((u32)obj, 0x1e);
    {
        s8 v = *((s8*)data + 0x18);
        s16 t = v << 8;
        *obj = t;
    }
}

/* slidingdoor_SeqFn: slidingdoor "think" routine. Tracks whether the player or
 * tricky is within lbl_803E43B8 xz-distance and steps a 3-bit state field
 * (state[0] bits 5..7) through the door's open/close machine. Returns 1
 * while in the static states (0/1) and 0 while in transition (2/3). */
int slidingdoor_SeqFn(u8* obj, int unused, ObjAnimUpdateState* animUpdate);

/* slidingdoor_update: triggered-once handler. If obj->_f4 is already set,
 * skip. Otherwise: if data->_1c (event id) is non-zero AND obj->_b8->_0
 * bits 5..7 are set, preempt the event. Then if (s8)data->_1e is not -1,
 * run that sequence with obj, -1.
 * Finally latch obj->_f4 = 1. */

/* exploded_init: store the map object tag, scale the model using the map
 * byte, then enable physics if any initial velocity/acceleration is present. */

/* attractor_func0B: dispatch on (s8)obj->_4c->_19 - state 0/3+ store NULL,
 * state 1 stores obj, state 2 computes atan2 of (player - obj) deltas
 * (truncated to int), latches angle+0x8000 into obj+0, then stores obj. */
void attractor_func0B(u8* obj, void** out)
{
    void* result = NULL;
    s8 state = *(s8*)((char*)(*(u8**)&((GameObject*)obj)->anim.placementData) + 0x19);
    switch (state)
    {
    case 0:
        break;
    case 1:
        result = obj;
        break;
    case 2:
        {
            u8* player = (u8*)Obj_GetPlayerObject();
            int angle = atan2i(
                (int)(((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX),
                (int)(((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ)
            );
            ((GameObject*)obj)->anim.rotX = (s16)(angle + 0x8000);
            result = obj;
            break;
        }
    }
    *out = result;
}

/* slidingdoor_init: clear obj+0xf4, copy data[0x1f]<<8 into obj+0; install
 * slidingdoor_SeqFn as obj->thinkRoutine; convert data[0x21] to f32, scale by
 * lbl_803E43C0 and obj->_50->[4], stash at obj+0x8; then clear bits 5..7 of
 * obj->_b8->_0. */
void slidingdoor_init(u8* obj, u8* data);

/* Exploded debris setup: seed object angles, linear velocity, angular velocity,
 * ground clearance, and the randomized lifetime countdown. */

/* Exploded debris physics step: integrate local velocity and spin, bounce from
 * the stored floor height, and return nonzero once the shard comes to rest. */
