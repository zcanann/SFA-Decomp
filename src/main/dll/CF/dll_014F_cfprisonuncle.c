/*
 * cfprisonuncle (DLL 0x14F) - the old CloudRunner imprisoned in the CF
 * dungeon. While caged he head-tracks the player, mutters, and runs
 * his dialog sequence on interaction; once his cage opens (GameBit
 * 0x4D - the cage placement's opened bit on clouddungeon) he runs his
 * release sequence, which thanks Fox (+2 magic here, the Power Room
 * key and the "restore the power to run the wind lifts" exposition via
 * the sequence script). Once he is gone (0x50) only his companion
 * object still renders. Carved from the sandwormBoss 10-DLL container.
 */
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/game_object.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"
#include "main/objprint.h"
#include "main/dll/fx_800944A0_shared.h"

extern int ObjMsg_Pop();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern bool ObjTrigger_UpdateIdBlockFlag(int obj);
extern int ObjTrigger_IsSet();
extern int ObjPath_GetPointWorldPosition();
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern u32 GameBit_Get(int eventId);

extern void playerAddRemoveMagic(void* player, int n);
extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern int objModelGetVecFn_800395d8(int obj, int idx);
extern void objAudioFn_80039270(int obj, void* p, int id);
extern void* ObjList_GetObjects(int* outA, int* outB);
extern f32 lbl_803E428C;
extern int objUpdateOpacity(int sub);
extern f32 lbl_803E4288;

STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

/* release-sequence callback: on the cued trigger, thank Fox with a
 * one-shot +2 magic (the Power Room key comes from the script) */
int fn_8019FC84(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    CfPrisonUncleState* p = ((GameObject*)obj)->extra;
    if (p->magicGranted != 0) return 0;
    if (animUpdate->triggerCommand == 2)
    {
        p->magicGranted = 1;
        playerAddRemoveMagic(Obj_GetPlayerObject(), 2);
    }
    return 0;
}

int cfprisonuncle_getExtraSize(void) { return 0xa8; }

int cfprisonuncle_getObjectTypeId(void) { return 0x9; }

void cfprisonuncle_free(void)
{
}

/* cfprisonuncle_render: render the uncle and/or his companion object
 * depending on the release gamebits, opacity and visibility; while
 * still caged, snap the uncle to the companion's path start first. */
void cfprisonuncle_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CfPrisonUncleState* sub = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x50) != 0)
    {
        if (*(void**)&sub->target != NULL && objUpdateOpacity(sub->target) != 0)
        {
            ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(sub->target, p2, p3, p4, p5, lbl_803E4288);
        }
    }
    else if (GameBit_Get(0x4d) != 0 && visible != 0)
    {
        ((void(*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E4288);
        if (*(void**)&sub->target != NULL && objUpdateOpacity(sub->target) != 0)
        {
            ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(sub->target, p2, p3, p4, p5, lbl_803E4288);
        }
    }
    else if (sub != NULL && *(void**)&sub->target != NULL)
    {
        if (sub->released == 0)
        {
            if (visible != 0)
            {
                if (objUpdateOpacity(sub->target) != 0)
                {
                    ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(
                        sub->target, p2, p3, p4, p5, lbl_803E4288);
                    ObjPath_GetPointWorldPosition(sub->target, 0, (char*)obj + 0xc, (char*)obj + 0x10,
                                                  (char*)obj + 0x14, 0);
                }
                ((void(*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E4288);
            }
        }
        else
        {
            if (objUpdateOpacity(sub->target) != 0)
            {
                ((void(*)(int, int, int, int, int, f32))
                    objRenderModelAndHitVolumes)(sub->target, p2, p3, p4, p5, lbl_803E4288);
            }
            if (visible != 0)
            {
                ((void(*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E4288);
            }
        }
    }
}

void cfprisonuncle_hitDetect(void)
{
}

/* cfprisonuncle_update: while still caged, drain pending messages,
 * re-acquire the companion object, then head-track the player and
 * mutter (running sequence 1 on interaction); once his cage is open,
 * disable interaction and run the release sequence. */
void cfprisonuncle_update(int* obj)
{
    CfPrisonUncleState* sub = ((GameObject*)obj)->extra;
    void* player;
    int m2, objectIndex, objectCount, m1, m3;
    int* objects;
    int i;
    if (sub == NULL) return;
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
            if (((GameObject*)objects[i])->anim.classId == 0x3d)
            {
                sub->target = objects[i];
                i = objectCount;
            }
        }
    }
    ObjTrigger_UpdateIdBlockFlag((int)obj);
    sub->released = GameBit_Get(0x4d);
    if (sub->released == 0)
    {
        player = Obj_GetPlayerObject();
        fn_8003ADC4(obj, player, (char*)((GameObject*)obj)->extra + 4, 0x41, 0, 3);
        if ((int)randomGetRange(0, 0x1e) == 0)
        {
            objAudioFn_80039270((int)obj, (char*)sub + 0x34, 0x297);
        }
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            s16* vec;
            fn_8003ADC4(obj, player, (char*)((GameObject*)obj)->extra + 4, 0x41, 0, 3);
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

void cfprisonuncle_init(int* obj)
{
    CfPrisonUncleState* state;
    ObjMsg_AllocQueue(obj, 1);
    ((GameObject*)obj)->animEventCallback = fn_8019FC84;
    state = ((GameObject*)obj)->extra;
    state->unk64 = 464;
    state->unk68 = 465;
    state->unk70 = 0;
    state->magicGranted = 0;
    if ((u32)GameBit_Get(0x4d) != 0u)
    {
        GameBit_Set(0x50, 1);
    }
}

void cfprisonuncle_release(void)
{
}

void cfprisonuncle_initialise(void)
{
}
