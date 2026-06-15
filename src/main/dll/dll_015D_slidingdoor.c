/* DLL 0x15D - SlidingDoor [801A39B4-801A39D0) */
#include "main/dll/drexplodable_types.h"
#include "main/obj_placement.h"

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

/* segment pragma-stack balance (re-split): */

#include "main/dll/IM/IMicicle.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct SlidingdoorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} SlidingdoorPlacement;

extern undefined8 FUN_80017698();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

extern f32 lbl_803E43BC;
extern void objRenderFn_8003b8f4(f32);
extern void* Obj_GetPlayerObject(void);
extern f32 lbl_803E43B8;
extern f32 lbl_803E43C0;
extern void* getTrickyObject(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);

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

void slidingdoor_free(void)
{
}

void slidingdoor_hitDetect(void)
{
}

void slidingdoor_release(void)
{
}

void slidingdoor_initialise(void)
{
}

void attractor_hitDetect(void);

int slidingdoor_getExtraSize(void) { return 0x1; }
int slidingdoor_getObjectTypeId(void) { return 0x0; }
int attractor_getExtraSize(void);

void slidingdoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43BC);
}

void attractor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* slidingdoor_SeqFn: slidingdoor "think" routine. Tracks whether the player or
 * tricky is within lbl_803E43B8 xz-distance and steps a 3-bit state field
 * (state[0] bits 5..7) through the door's open/close machine. Returns 1
 * while in the static states (0/1) and 0 while in transition (2/3). */
int slidingdoor_SeqFn(u8* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    typedef struct DoorFlags
    {
        u8 mode : 3;
        u8 rest : 5;
    } DoorFlags;
    register int playerNear;
    register int trickyNear;
    register u8* state;
    u8* params;
    u32 mode;
    int result;
    void* player;
    void* tricky;

    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();

    if (player != NULL)
    {
        playerNear = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            lbl_803E43B8;
    }
    else
    {
        playerNear = 0;
    }

    if (tricky != NULL)
    {
        trickyNear = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)((u8*)tricky + 0x18)) < lbl_803E43B8;
    }
    else
    {
        trickyNear = 0;
    }

    state = ((GameObject*)obj)->extra;
    params = *(u8**)&((GameObject*)obj)->anim.placementData;
    mode = ((u32)state[0] >> 5) & 7;

    if (mode == 0)
    {
        if (GameBit_Get(((SlidingdoorPlacement*)params)->unk18) != 0 &&
            (((SlidingdoorPlacement*)params)->unk22 == -1 ||
                GameBit_Get(((SlidingdoorPlacement*)params)->unk22) != 0))
        {
            GameBit_Set(((SlidingdoorPlacement*)params)->unk1A, 1);
            if (playerNear != 0 || trickyNear != 0)
            {
                ((DoorFlags*)state)->mode = 2;
            }
        }
    }
    else if (mode == 1)
    {
        if ((GameBit_Get(((SlidingdoorPlacement*)params)->unk18) != 0 ||
                (((SlidingdoorPlacement*)params)->unk22 != -1 &&
                    GameBit_Get(((SlidingdoorPlacement*)params)->unk22) != 0)) &&
            playerNear == 0 && trickyNear == 0)
        {
            ((DoorFlags*)state)->mode = 3;
        }
    }

    {
        register DoorFlags* fl = (DoorFlags*)state;
        if (fl->mode == 2)
        {
            if (animUpdate->triggerCommand == 2)
            {
                fl->mode = 1;
            }
        }
        else if (fl->mode == 3)
        {
            if (animUpdate->triggerCommand == 1)
            {
                fl->mode = 0;
            }
        }
    }

    result = 0;
    {
        u32 m3 = ((u32)state[0] >> 5) & 7;
        if (m3 != 2)
        {
            if (m3 != 3) result = 1;
        }
    }
    return result;
}

/* slidingdoor_update: triggered-once handler. If obj->_f4 is already set,
 * skip. Otherwise: if data->_1c (event id) is non-zero AND obj->_b8->_0
 * bits 5..7 are set, preempt the event. Then if (s8)data->_1e is not -1,
 * run that sequence with obj, -1.
 * Finally latch obj->_f4 = 1. */
void slidingdoor_update(u8* obj)
{
    u8* sub;
    u8* data;
    if (((GameObject*)obj)->unkF4 != 0) return;
    sub = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((SlidingdoorPlacement*)data)->unk1C != 0)
    {
        u32 mode = (u32)((sub[0] >> 5) & 7);
        if (mode != 0)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, ((SlidingdoorPlacement*)data)->unk1C);
        }
    }
    {
        s8 id = (s8)data[0x1e];
        if (id != -1)
        {
            (*gObjectTriggerInterface)->runSequence(id, obj, -1);
        }
    }
    *(u32*)&((GameObject*)obj)->unkF4 = 1;
}

/* exploded_init: store the map object tag, scale the model using the map
 * byte, then enable physics if any initial velocity/acceleration is present. */
void exploded_init(ExplodedObject* obj, ExplodedObjectMapData* data, int extra);

/* attractor_func0B: dispatch on (s8)obj->_4c->_19 - state 0/3+ store NULL,
 * state 1 stores obj, state 2 computes atan2 of (player - obj) deltas
 * (truncated to int), latches angle+0x8000 into obj+0, then stores obj. */

/* slidingdoor_init: clear obj+0xf4, copy data[0x1f]<<8 into obj+0; install
 * slidingdoor_SeqFn as obj->thinkRoutine; convert data[0x21] to f32, scale by
 * lbl_803E43C0 and obj->_50->[4], stash at obj+0x8; then clear bits 5..7 of
 * obj->_b8->_0. */
void slidingdoor_init(u8* obj, u8* data)
{
    typedef struct SlidingDoorSubFlags
    {
        u8 doorState : 3;
        u8 rest : 5;
    } SlidingDoorSubFlags;
    u8* sub;
    f32 v;
    u32 doorState = 0;
    *(u32*)&((GameObject*)obj)->unkF4 = doorState;
    ((GameObject*)obj)->anim.rotX = (s16)(data[0x1f] << 8);
    ((GameObject*)obj)->animEventCallback = (void*)slidingdoor_SeqFn;
    v = (f32)(u32)
    data[0x21] * lbl_803E43C0;
    ((GameObject*)obj)->anim.rootMotionScale = v;
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    sub = ((GameObject*)obj)->extra;
    ((SlidingDoorSubFlags*)sub)->doorState = doorState;
}

/* Exploded debris setup: seed object angles, linear velocity, angular velocity,
 * ground clearance, and the randomized lifetime countdown. */

/* Exploded debris physics step: integrate local velocity and spin, bounce from
 * the stored floor height, and return nonzero once the shard comes to rest. */
