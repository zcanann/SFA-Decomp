#include "main/dll/mmshrine/shrine.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"

typedef struct MmshScalesState
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x14 - 0x10];
    s32 unk14;
    u8 pad18[0x24 - 0x18];
    f32 unk24;
    s32 unk28;
    u8 pad2C[0x6A - 0x2C];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x140 - 0x70];
} MmshScalesState;

extern void Obj_FreeObject(void* obj);
extern int* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

extern u8 lbl_803DB411;
extern f32 lbl_803E4F68;
extern void objRenderFn_8003b8f4(f32);
extern void* ObjList_FindObjectById(int id);
extern f32 lbl_803E4F78;
extern u8 Obj_IsLoadingLocked(void);
extern u8* Obj_AllocObjectSetup(int size, int type);
extern u8* Obj_SetupObject(u8* no, int a, int b, int c, int d);

void mmsh_scales_free(int obj, int arg2)
{
    void* child;
    (*gObjectTriggerInterface)->freeState(((GameObject*)obj)->extra);
    (*(code*)(*gTitleMenuControlInterface + 8))(obj, 0xffff, 0, 0, 0);
    child = ((GameObject*)obj)->childObjs[0];
    if ((child != NULL) && (arg2 == 0))
    {
        Obj_FreeObject(child);
    }
    return;
}

void mmsh_scales_update(int objArg)
{
    int typeId;
    int* list;
    int obj;
    int found;
    int id;
    int n;
    int i;
    int count;

    if ((((GameObject*)objArg)->anim.placementData != NULL) && (*(short*)(*(int*)&((GameObject*)objArg)->anim.
        placementData + 0x18) != -1))
    {
        i = (*gObjectTriggerInterface)->update((u8*)objArg, (f32)(u32)lbl_803DB411);
        if ((i != 0) && (((GameObject*)objArg)->seqIndex == -2))
        {
            typeId = *(s8*)(*(int*)&((GameObject*)objArg)->extra + 0x57);
            found = 0;
            list = (int*)ObjList_GetObjects(&i, &count);
            n = 0;
            for (i = 0, id = (int)(s8)typeId; i < count; i++)
            {
                obj = *list;
                if (((GameObject*)obj)->seqIndex == typeId)
                {
                    found = obj;
                }
                if (((((GameObject*)obj)->seqIndex == -2) && (((GameObject*)obj)->anim.classId == 0x10)) &&
                    (id == *(char*)(*(int*)&((GameObject*)obj)->extra + 0x57)))
                {
                    n = n + 1;
                }
                list = list + 1;
            }
            if (((n <= 1) && ((u32)found != 0)) && (*(short*)(found + 0xb4) != -1))
            {
                *(s16*)(found + 0xb4) = -1;
                (*gObjectTriggerInterface)->endSequence(id);
            }
            ((GameObject*)objArg)->seqIndex = -1;
            Obj_FreeObject((void*)objArg);
        }
    }
    return;
}

void mmsh_shrine_release(void);

void mmsh_scales_hitDetect(void)
{
}

void mmsh_scales_release(void)
{
}

void mmsh_scales_initialise(void)
{
}

void mmsh_waterspike_free(void);

int mmsh_scales_getExtraSize(void) { return 0x140; }
int mmsh_scales_getObjectTypeId(void) { return 0xb; }
int mmsh_waterspike_getExtraSize(void);

void mmsh_scales_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4F68);
}

void mmsh_waterspike_update(int obj);

void mmsh_scales_init(int* obj, s16* def)
{
    u8* state = ((GameObject*)obj)->extra;
    u8* no;
    int active;
    ((MmshScalesState*)state)->unk6A = def[13];
    ((MmshScalesState*)state)->unk6E = -1;
    ((MmshScalesState*)state)->unk24 = lbl_803E4F68 / (lbl_803E4F68 + (f32)(u32) * (u8*)((char*)def + 36));
    ((MmshScalesState*)state)->unk28 = -1;
    active = ((GameObject*)obj)->unkF4;
    if (active == 0 && def[12] != 1)
    {
        (*gObjectTriggerInterface)->loadAnimData(state, (u8*)def);
        ((GameObject*)obj)->unkF4 = (int)def[12] + 1;
    }
    else if (active != 0 && def[12] != active - 1)
    {
        (*gObjectTriggerInterface)->freeState(state);
        if (def[12] != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData(state, (u8*)def);
        }
        ((GameObject*)obj)->unkF4 = (int)def[12] + 1;
    }
    if (Obj_IsLoadingLocked() == 0) return;
    no = Obj_AllocObjectSetup(0x24, 0x1b8);
    *(f32*)(no + 8) = ((GameObject*)obj)->anim.localPosX;
    *(f32*)(no + 12) = ((GameObject*)obj)->anim.localPosY;
    *(f32*)(no + 16) = ((GameObject*)obj)->anim.localPosZ;
    no[4] = 32;
    no[5] = 4;
    no[7] = 0xff;
    no = Obj_SetupObject(no, 5, -1, -1, 0);
    ((GameObject*)obj)->childObjs[0] = no;
    *(f32*)(*(u8**)&((GameObject*)obj)->childObjs[0] + 8) = *(f32*)(*(u8**)&((GameObject*)obj)->childObjs[0] + 8) *
        lbl_803E4F78;
}
