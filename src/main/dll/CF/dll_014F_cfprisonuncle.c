/*
 * cfprisonuncle (DLL 0x14F) - the imprisoned CloudRunner elder at CF.
 * update head-tracks the player, mutters ambient barks, runs sequence
 * 1 on interaction and sequence 0 once GameBit 0x4D marks the rescue.
 * Carved from the sandwormBoss 10-DLL container.
 */
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_EnableObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();
extern bool ObjTrigger_UpdateIdBlockFlag(int obj);
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 objAnimFn_80038f38();
extern void objRenderFn_8003b8f4(f32);

extern ObjectTriggerInterface** gObjectTriggerInterface;

extern uint GameBit_Get(int eventId);
extern void* Obj_GetPlayerObject(void);
extern void playerAddRemoveMagic(void* player, int n);
extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern int objModelGetVecFn_800395d8(int obj, int idx);
extern void objAudioFn_80039270(int obj, void* p, int id);
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern u8 framesThisStep;
extern f32 lbl_803E428C;
extern int objUpdateOpacity(int sub);
extern f32 lbl_803E4288;


void babycloudrunner_init_OLD_v1_1(int obj)
{
    undefined4* state;

    state = ((GameObject*)obj)->extra;
    *state = 0;
    state[1] = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0x80;
    return;
}


void cfguardian_release(void);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */

/* Per-object extra state for the CloudRunner main crystal
 * (cfmaincrystal_getExtraSize == 0x160). */


/* Per-object extra state for the CloudRunner power base
 * (cfpowerbase_getExtraSize == 0x6). */


/* Per-object extra state for the CloudRunner prison guard
 * (cfprisonguard_getExtraSize == 0x3c). */


/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */

STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */


void cfprisonuncle_free(void)
{
}

void cfprisonuncle_hitDetect(void)
{
}

void cfprisonuncle_release(void)
{
}

void cfprisonuncle_initialise(void)
{
}

/* EN v1.0 0x8019FEDC  size: 536b  cfprisonuncle_update: while not captured,
 * drain pending messages, re-acquire the keyed target object, then either
 * track/animate toward the player (firing the alert trigger) or, once
 * captured, raise the done flag and notify. */
#pragma scheduling off
#pragma peephole off
void cfprisonuncle_update(int* obj)
{
    CfPrisonUncleState* sub = ((GameObject*)obj)->extra;
    void* player;
    int m2, objectIndex, objectCount, m1, m3;
    int* objects;
    int i;
    if (sub == NULL) return;
    /* 0x50: the prisoners are free - nothing left to do */
    if (GameBit_Get(0x50) != 0) return;
    if (ObjMsg_Pop(obj, &m1, &m2, &m3) != 0)
    {
        *(void**)&sub->target = NULL;
    }
    if (*(void**)&sub->target == NULL)
    {
        objects = ObjList_GetObjects(&objectIndex, &objectCount);
        for (i = objectIndex; i < objectCount; i++)
        {
            /* find the guard (object class 0x3D) to glance at */
            if (((GameObject*)objects[i])->anim.classId == 0x3d)
            {
                sub->target = objects[i];
                i = objectCount;
            }
        }
    }
    ObjTrigger_UpdateIdBlockFlag((int)obj);
    /* 0x4D: the player has been thrown into the cell */
    sub->captured = (s8)GameBit_Get(0x4d);
    if (sub->captured == 0)
    {
        player = Obj_GetPlayerObject();
        fn_8003ADC4(obj, player, (char*)((GameObject*)obj)->extra + 4, 0x41, 0, 3);
        /* roughly every half second, mutter (sfx 0x297) */
        if ((int)randomGetRange(0, 0x1e) == 0)
        {
            objAudioFn_80039270((int)obj, (char*)sub + 0x34, 0x297);
        }
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            s16* vec;
            fn_8003ADC4(obj, player, (char*)((GameObject*)obj)->extra + 4, 0x41, 0, 3);
            /* tilt the head back for the talk animation */
            vec = (s16*)objModelGetVecFn_800395d8((int)obj, 1);
            *vec = -0xaaa;
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        }
        else
        {
            objAnimFn_80038f38((int)obj, (char*)sub + 0x34);
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(
                (int)obj, lbl_803E428C, (f32)(u32)framesThisStep, 0);
        }
    }
    else
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        if (((GameObject*)obj)->seqIndex == -1)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
}
void gcrobotlightbea_render(void);

int cfprisonuncle_getExtraSize(void) { return 0xa8; }
int cfprisonuncle_getObjectTypeId(void) { return 0x9; }
int gcrobotlightbea_getExtraSize(void);

#pragma scheduling on
int fn_8019FC84(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    CfPrisonUncleState* p = ((GameObject*)obj)->extra;
    if (p->kicked != 0) return 0;
    if (animUpdate->triggerCommand == 2)
    {
        p->kicked = 1;
        playerAddRemoveMagic(Obj_GetPlayerObject(), 2);
    }
    return 0;
}

#pragma scheduling off
void cfprisonuncle_init(int* obj)
{
    CfPrisonUncleState* state;
    ObjMsg_AllocQueue(obj, 1);
    ((GameObject*)obj)->animEventCallback = (void*)fn_8019FC84;
    state = ((GameObject*)obj)->extra;
    state->unk64 = 464;
    state->unk68 = 465;
    state->unk70 = 0;
    state->kicked = 0;
    if ((u32)GameBit_Get(77) != 0u)
    {
        GameBit_Set(80, 1);
    }
}

void cfguardian_hitDetect(int* obj);

/* EN v1.0 0x8019FCF4  size: 484b  cfprisonuncle_render: render the uncle and/or
 * his held model depending on the rescue gamebits, opacity and visibility;
 * when path-following, snap the held model to the path point first. */
void cfprisonuncle_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CfPrisonUncleState* sub = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x50) != 0)
    {
        if (*(void**)&sub->target != NULL && objUpdateOpacity(sub->target) != 0)
        {
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(sub->target, p2, p3, p4, p5, lbl_803E4288);
        }
    }
    else if (GameBit_Get(0x4d) != 0 && visible != 0)
    {
        ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4288);
        if (*(void**)&sub->target != NULL && objUpdateOpacity(sub->target) != 0)
        {
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(sub->target, p2, p3, p4, p5, lbl_803E4288);
        }
    }
    else if (sub != NULL && *(void**)&sub->target != NULL)
    {
        if (sub->captured == 0)
        {
            if (visible != 0)
            {
                if (objUpdateOpacity(sub->target) != 0)
                {
                    ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(
                        sub->target, p2, p3, p4, p5, lbl_803E4288);
                    ObjPath_GetPointWorldPosition(sub->target, 0, (char*)obj + 0xc, (char*)obj + 0x10,
                                                  (char*)obj + 0x14, 0);
                }
                ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4288);
            }
        }
        else
        {
            if (objUpdateOpacity(sub->target) != 0)
            {
                ((void(*)(int, int, int, int, int, f32))
                    objRenderFn_8003b8f4)(sub->target, p2, p3, p4, p5, lbl_803E4288);
            }
            if (visible != 0)
            {
                ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4288);
            }
        }
    }
}
