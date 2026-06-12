/* === moved from main/dll/DR/gasventControl.c [801A39B4-801A39D0) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/dll/DR/dll_015A_explodable.h"
#include "main/dll/dr_types.h"
#include "main/obj_placement.h"



/*
 * --INFO--
 *
 * Function: blasted_init
 * EN v1.0 Address: 0x801A2AF8
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801A2B9C
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801a2cb8
 * EN v1.0 Address: 0x801A2CB8
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801A2D6C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801a32d4
 * EN v1.0 Address: 0x801A32D4
 * EN v1.0 Size: 800b
 * EN v1.1 Address: 0x801A3190
 * EN v1.1 Size: 676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */






/* 8b "li r3, N; blr" returners. */







/* explodable_getExtraSize == 0x6e8 (gas-vent explodable). */
/* Per-fragment record inside DrExplodableState (stride 0x70). */


STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);



STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);


#pragma scheduling off
#pragma peephole off













#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/mapEvent.h"
#include "main/dll/IM/IMicicle.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct CfmagicwallPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} CfmagicwallPlacement;








extern undefined8 FUN_80017698();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern uint GameBit_Get(int eventId);

/*
 * --INFO--
 *
 * Function: cfforcefield_update
 * EN v1.0 Address: 0x801A39D0
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: 0x801A3B20
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801a4520
 * EN v1.0 Address: 0x801A4520
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801A4660
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_801a45cc
 * EN v1.0 Address: 0x801A45CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A4708
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a45cc(short* param_1, int param_2)
{
}


/*
 * --INFO--
 *
 * Function: cflevelcontrol_free
 * EN v1.0 Address: 0x801A45D4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801A4880
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cflevelcontrol_free(int param_1);


/*
 * --INFO--
 *
 * Function: FUN_801a4810
 * EN v1.0 Address: 0x801A4810
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801A4AD8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a4810(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             undefined4 param_9, undefined4 param_10, int param_11)
{
    undefined4 uVar1;
    int iVar2;
    undefined8 uVar3;

    for (iVar2 = 0; iVar2 < (int)(uint) * (byte*)(param_11 + 0x8b); iVar2 = iVar2 + 1)
    {
        if (*(char*)(param_11 + iVar2 + 0x81) == '\x01')
        {
            FUN_80017698(0xdcb, 1);
            uVar3 = FUN_80017698(0x4a3, 0);
            FUN_80041ff8(uVar3, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x2b);
            FUN_80042b9c(0, 0, 1);
            uVar1 = FUN_80044404(0x2b);
            FUN_80042bec(uVar1, 0);
        }
    }
    return 0;
}


/* Trivial 4b 0-arg blr leaves. */
void cfforcefield_release(void);










void cfmagicwall_free(void)
{
}

void cfmagicwall_hitDetect(void)
{
}

void cfmagicwall_release(void)
{
}

void cfmagicwall_initialise(void)
{
}

void cflevelcontrol_hitDetect(void);









/* 8b "li r3, N; blr" returners. */
int cfmagicwall_getExtraSize(void) { return 0x0; }
int cfmagicwall_getObjectTypeId(void) { return 0x0; }
int cflevelcontrol_getExtraSize(void);

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E43D8;
extern f32 lbl_803E43DC;
extern void* Obj_GetPlayerObject(void);
extern f32 Vec_distance(void* a, void* b);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);



void cfmagicwall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43D8);
}

void cflevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


void cfmagicwall_update(int obj)
{
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int player = (int)Obj_GetPlayerObject();
    int alpha = 0xff;

    if (GameBit_Get(((CfmagicwallPlacement*)data)->unk20) != 0)
    {
        int yaw = (s16)Obj_GetYawDeltaToObject(obj, player, NULL);

        if (yaw < 0)
        {
            yaw = -yaw;
        }

        if (yaw > 0x4000)
        {
            ((GameObject*)obj)->anim.alpha = 0;
            return;
        }

        {
            f32 playerDistance;
            f32 range;
            f32 fadeDistance;
            range = (f32)(s32)((CfmagicwallPlacement*)data)->unk1A;
            playerDistance = Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX, (void*)(player + 0x18));
            fadeDistance = Camera_DistanceToCurrentViewPosition(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ);

            if (fadeDistance < playerDistance)
            {
                fadeDistance = Camera_DistanceToCurrentViewPosition(
                    ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ);
            }
            else
            {
                fadeDistance = playerDistance;
            }

            if (fadeDistance < range)
            {
                alpha = (s32)(lbl_803E43DC * (fadeDistance / range));
            }

            ((GameObject*)obj)->anim.alpha = alpha;
        }
    }
}

extern int ObjList_FindObjectById(int objectId);


/* ObjGroup_RemoveObject(x, N) wrappers. */

/* state encode: ((obj->_X)->_Y << shift) | const. */

/* byte-to-short shift8 pattern. */
void cfmagicwall_init(s16* dst, void* src)
{
    s8 v = *((s8*)src + 0x18);
    s16 t = v << 8;
    *dst = t;
}

/* attractor_setScale: branch on s8 flag at +0x19 of obj->_4C; if set return s16 at +0x1a, else 0. */
int attractor_setScale(int* obj);

/* attractor_init: ObjGroup_AddObject(obj, 0x1e); byte<<8 -> sth at obj. */




/* slidingdoor_SeqFn: slidingdoor "think" routine. Tracks whether the player or
 * tricky is within lbl_803E43B8 xz-distance and steps a 3-bit state field
 * (state[0] bits 5..7) through the door's open/close machine. Returns 1
 * while in the static states (0/1) and 0 while in transition (2/3). */

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

/* slidingdoor_init: clear obj+0xf4, copy data[0x1f]<<8 into obj+0; install
 * slidingdoor_SeqFn as obj->thinkRoutine; convert data[0x21] to f32, scale by
 * lbl_803E43C0 and obj->_50->[4], stash at obj+0x8; then clear bits 5..7 of
 * obj->_b8->_0. */



/* cfforcefield_init: byte<<8 sth; insert GameBit_Get bit into bit-7 of *(u8*)obj->_B8; storeZeroToFloatParam. */





/* Exploded debris setup: seed object angles, linear velocity, angular velocity,
 * ground clearance, and the randomized lifetime countdown. */

/* Exploded debris physics step: integrate local velocity and spin, bounce from
 * the stored floor height, and return nonzero once the shard comes to rest. */
