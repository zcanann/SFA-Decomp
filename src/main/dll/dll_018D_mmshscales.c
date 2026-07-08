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
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/gameplay_runtime.h"
#include "main/dll/dll_018D_mmshscales.h"

/* Child object spawned at init and cached in childObjs[0] (scaled x2). */
#define MMSHSCALES_CHILD_OBJ 0x1b8

extern int* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

extern u8 lbl_803DB411;

extern void Obj_FreeObject(u8* obj);
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern u8* Obj_SetupObject(u8* no, int a, int b, int c, int d);

int MMSH_Scales_getExtraSize(void)
{
    return 0x140;
}
int MMSH_Scales_getObjectTypeId(void)
{
    return 0xb;
}

void MMSH_Scales_free(int obj, int keepChild)
{
    void* child;
    (*gObjectTriggerInterface)->freeState(((GameObject*)obj)->extra);
    (*(void (**)(int, u16, int, int, int))((char*)*gTitleMenuControlInterface + 8))(obj, 0xffff, 0, 0, 0);
    child = ((GameObject*)obj)->childObjs[0];
    if ((child != NULL) && (keepChild == 0))
    {
        Obj_FreeObject(child);
    }
}

void MMSH_Scales_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void MMSH_Scales_hitDetect(void)
{
}

void MMSH_Scales_update(int objArg)
{
    int seqTag;
    int* list;
    int other;
    int match;
    int groupTag;
    int siblingCount;
    int i;
    int count;

    if ((((GameObject*)objArg)->anim.placementData != NULL) &&
        (*(short*)(*(int*)&((GameObject*)objArg)->anim.placementData + 0x18) != -1))
    {
        i = (*gObjectTriggerInterface)->update((u8*)objArg, (f32)(u32)lbl_803DB411);
        if ((i != 0) && (((GameObject*)objArg)->seqIndex == -2))
        {
            seqTag = *(s8*)(*(int*)&((GameObject*)objArg)->extra + 0x57);
            match = 0;
            list = ObjList_GetObjects(&i, &count);
            siblingCount = 0;
            for (i = 0, groupTag = (int)(s8)seqTag; i < count; i++)
            {
                other = *list;
                if (((GameObject*)other)->seqIndex == seqTag)
                {
                    match = other;
                }
                if (((((GameObject*)other)->seqIndex == -2) && (((GameObject*)other)->anim.classId == 0x10)) &&
                    (groupTag == *(s8*)(*(int*)&((GameObject*)other)->extra + 0x57)))
                {
                    siblingCount++;
                }
                list = list + 1;
            }
            if (((siblingCount <= 1) && ((u32)match != 0)) && (*(short*)(match + 0xb4) != -1))
            {
                ((GameObject*)match)->seqIndex = -1;
                (*gObjectTriggerInterface)->endSequence(groupTag);
            }
            ((GameObject*)objArg)->seqIndex = -1;
            Obj_FreeObject((void*)objArg);
        }
    }
}

void MMSH_Scales_init(int* obj, s16* def)
{
    u8* state = ((GameObject*)obj)->extra;
    MmshScalesSpawnSetup* setup;
    int loadedBank;
    ((MmshScalesState*)state)->unk6A = def[13];
    ((MmshScalesState*)state)->unk6E = -1;
    ((MmshScalesState*)state)->dampingFactor = 1.0f / (1.0f + (f32)(u32)((u8*)def)[36]);
    ((MmshScalesState*)state)->unk28 = -1;
    loadedBank = ((GameObject*)obj)->unkF4;
    if (loadedBank == 0 && def[12] != 1)
    {
        (*gObjectTriggerInterface)->loadAnimData(state, (u8*)def);
        ((GameObject*)obj)->unkF4 = def[12] + 1;
    }
    else if (loadedBank != 0 && def[12] != loadedBank - 1)
    {
        (*gObjectTriggerInterface)->freeState(state);
        if (def[12] != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData(state, (u8*)def);
        }
        ((GameObject*)obj)->unkF4 = def[12] + 1;
    }
    if (Obj_IsLoadingLocked() == 0)
        return;
    setup = Obj_AllocObjectSetup(0x24, MMSHSCALES_CHILD_OBJ);
    setup->posX = ((GameObject*)obj)->anim.localPosX;
    setup->posY = ((GameObject*)obj)->anim.localPosY;
    setup->posZ = ((GameObject*)obj)->anim.localPosZ;
    setup->color[0] = 32;
    setup->color[1] = 4;
    setup->color[3] = 0xff;
    ((GameObject*)obj)->childObjs[0] = Obj_SetupObject((u8*)setup, 5, -1, -1, 0);
    *(f32*)(*(u8**)&((GameObject*)obj)->childObjs[0] + 8) *= 2.0f;
}

void MMSH_Scales_release(void)
{
}

void MMSH_Scales_initialise(void)
{
}
