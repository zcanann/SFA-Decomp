/*
 * mmsh_scales (DLL 0x018D) - a trigger-sequence "scales" object in the
 * Moon Mountain Shrine (mmsh) family; object type id 0xb.
 *
 * init() loads the object's animation/sequence data from its placement def
 * (re-loading only when the def's bank index changes), seeds the per-object
 * state, and - while the loader is locked - spawns a child object at the
 * object's world position and scales the child by lbl_803E4F78.
 *
 * update() advances the trigger sequence each frame; once the sequence has
 * ended (seqIndex == -2) it scans the live object list for sibling scales of
 * the same group tag (extra+0x57), ends the shared sequence when this is the
 * last one, and frees itself.
 *
 * free() releases the trigger state, notifies the title-menu control
 * interface (vtable slot 2), and frees the spawned child.
 */
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_list.h"
#include "main/objseq.h"
#include "main/dll/dll_018D_mmshscales.h"
#include "main/object_render.h"
#include "main/dll/dll_0004_dummy04.h"

/* Child object spawned at init and cached in childObjs[0] (scaled x2);
   retail OBJECTS.bin name "scalessword" (DLL 0x12A). */
#define MMSHSCALES_CHILD_OBJ_SWORD 0x1b8

extern u8 lbl_803DB411;


int MMSH_Scales_getExtraSize(void)
{
    return 0x140;
}
int MMSH_Scales_getObjectTypeId(void)
{
    return 0xb;
}

void MMSH_Scales_free(GameObject* obj, int keepChild)
{
    GameObject* child;
    (*gObjectTriggerInterface)->freeState(obj->extra);
    gTitleMenuControlInterfaceCopy->vtable->func05((void*)obj, 0xffff, 0, 0, 0);
    child = obj->childObjs[0];
    if ((child != NULL) && (keepChild == 0))
    {
        Obj_FreeObject(child);
    }
}

void MMSH_Scales_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void MMSH_Scales_hitDetect(void)
{
}

void MMSH_Scales_update(GameObject* obj)
{
    int seqTag;
    GameObject** list;
    GameObject* other;
    GameObject* match;
    int groupTag;
    int siblingCount;
    int i;
    int count;

    if ((obj->anim.placementData != NULL) &&
        (((MmshScalesPlacement*)obj->anim.placementData)->animationBank != -1))
    {
        i = (*gObjectTriggerInterface)->update((u8*)obj, (f32)(u32)lbl_803DB411);
        if ((i != 0) && (obj->seqIndex == -2))
        {
            seqTag = ((MmshScalesState*)obj->extra)->groupTag;
            match = NULL;
            list = (GameObject**)ObjList_GetObjects(&i, &count);
            siblingCount = 0;
            for (i = 0, groupTag = (int)(s8)seqTag; i < count; i++)
            {
                other = *list;
                if (other->seqIndex == seqTag)
                {
                    match = other;
                }
                if (((other->seqIndex == -2) && (other->anim.classId == 0x10)) &&
                    (groupTag == ((MmshScalesState*)other->extra)->groupTag))
                {
                    siblingCount++;
                }
                list = list + 1;
            }
            if (((siblingCount <= 1) && ((u32)match != 0)) && (match->seqIndex != -1))
            {
                match->seqIndex = -1;
                (*gObjectTriggerInterface)->endSequence(groupTag);
            }
            obj->seqIndex = -1;
            Obj_FreeObject(obj);
        }
    }
}

void MMSH_Scales_init(GameObject* obj, MmshScalesPlacement* placement)
{
    MmshScalesState* state = obj->extra;
    MmshScalesSpawnSetup* setup;
    int loadedBank;
    state->unk6A = placement->sequenceTag;
    state->unk6E = -1;
    state->dampingFactor = 1.0f / (1.0f + (f32)(u32)placement->damping);
    state->unk28 = -1;
    loadedBank = obj->userData1;
    if (loadedBank == 0 && placement->animationBank != 1)
    {
        (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)placement);
        obj->userData1 = placement->animationBank + 1;
    }
    else if (loadedBank != 0 && placement->animationBank != loadedBank - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)state);
        if (placement->animationBank != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)placement);
        }
        obj->userData1 = placement->animationBank + 1;
    }
    if (Obj_IsLoadingLocked() == 0)
        return;
    setup = (MmshScalesSpawnSetup*)Obj_AllocObjectSetup(0x24, MMSHSCALES_CHILD_OBJ_SWORD);
    setup->base.posX = obj->anim.localPosX;
    setup->base.posY = obj->anim.localPosY;
    setup->base.posZ = obj->anim.localPosZ;
    setup->base.color[0] = 32;
    setup->base.color[1] = 4;
    setup->base.color[3] = 0xff;
    obj->childObjs[0] = Obj_SetupObject((ObjPlacement*)setup, 5, -1, -1, NULL);
    ((GameObject*)obj->childObjs[0])->anim.rootMotionScale *= 2.0f;
}

void MMSH_Scales_release(void)
{
}

void MMSH_Scales_initialise(void)
{
}
