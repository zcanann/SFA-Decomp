#include "main/dll/mmshrine/shrine.h"
#include "main/dll/laser19F.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"

typedef struct MmshWaterspikePlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x14 - 0x10];
    s32 unk14;
} MmshWaterspikePlacement;


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


typedef struct MmshWaterspikeObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x24 - 0x1E];
    u8 unk24;
    u8 pad25[0x28 - 0x25];
} MmshWaterspikeObjectDef;


extern u32 randomGetRange(int min, int max);
extern void fn_801C4664(void* obj);
extern undefined4 SH_LevelControl_runBloopEvent();
extern int objCreateLight(int param_1, int param_2);
extern void GameBit_Set(int eventId, int value);
extern void Obj_FreeObject(void* obj);

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern int* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern f64 DOUBLE_803e5bd0;
extern f64 DOUBLE_803e5c08;
extern f32 lbl_803DC074;
extern f32 lbl_803E5BD8;
extern f32 lbl_803E5BE8;

/*
 * --INFO--
 *
 * Function: mmsh_shrine_init
 * EN v1.0 Address: 0x801C52D8
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x801C533C
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mmsh_shrine_init(undefined2* obj, int arg2);

/*
 * --INFO--
 *
 * Function: mmsh_scales_free
 * EN v1.0 Address: 0x801C53B0
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x801C5418
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: mmsh_scales_update
 * EN v1.0 Address: 0x801C5474
 * EN v1.0 Size: 372b
 */
extern u8 lbl_803DB411;

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
            for (i = 0, id = typeId; i < count; i++)
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


/* Trivial 4b 0-arg blr leaves. */
void mmsh_shrine_release(void);

void mmsh_shrine_initialise(void);

void mmsh_scales_hitDetect(void)
{
}

void mmsh_scales_release(void)
{
}

void mmsh_scales_initialise(void)
{
}

void mmsh_waterspike_free(void)
{
}

void mmsh_waterspike_hitDetect(void)
{
}

void mmsh_waterspike_release(void)
{
}

void mmsh_waterspike_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int mmsh_scales_getExtraSize(void) { return 0x140; }
int mmsh_scales_getObjectTypeId(void) { return 0xb; }
int mmsh_waterspike_getExtraSize(void) { return 0x0; }
int mmsh_waterspike_getObjectTypeId(void) { return 0x0; }
void mmsh_waterspike_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4F68;
extern void objRenderFn_8003b8f4(f32);

void mmsh_scales_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4F68);
}

/*
 * --INFO--
 *
 * Function: mmsh_waterspike_update
 * EN v1.0 Address: 0x801C57B0
 * EN v1.0 Size: 380b
 */
extern void* ObjList_FindObjectById(int id);
extern f32 objFn_801948c0(void* obj, int param_2);
extern void fn_80137948(char* fmt, ...);
extern char sWaterSpikeInvalidXyzAnimIdWarning[];
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int** out, int a, int b);
extern u8 framesThisStep;
extern WaterfxInterface** gWaterfxInterface;
extern f32 lbl_803E4F80;
extern f32 lbl_803E4F84;
extern f32 lbl_803E4F88;

void mmsh_waterspike_update(int obj)
{
    void* o;
    int* p;
    int obj2;
    int n;
    int i;
    f32 d;
    f32 newY;
    f32 maxY;
    f32 dist;
    int* list;
    int state;

    state = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjHits_SetHitVolumeSlot(obj, 9, 1, 0);
    o = ObjList_FindObjectById(((GameObject*)obj)->unkF8);
    if (o != NULL)
    {
        dist = objFn_801948c0(o, 3) - ((GameObject*)obj)->anim.localPosY;
    }
    else
    {
        fn_80137948(sWaterSpikeInvalidXyzAnimIdWarning, ((MmshWaterspikePlacement*)state)->unk14);
        n = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX,
                                 ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, &list, 0, 0);
        if (n != 0)
        {
            dist = lbl_803E4F80;
            p = list;
            for (i = 0; i < n; i++)
            {
                obj2 = *p;
                if (*(char*)(obj2 + 0x14) == 0xe)
                {
                    d = *(f32*)obj2 - ((GameObject*)obj)->anim.localPosY;
                    if (d > dist)
                    {
                        dist = d;
                    }
                }
                p = p + 1;
            }
        }
    }
    newY = ((GameObject*)obj)->anim.localPosY + dist;
    maxY = ((MmshWaterspikePlacement*)state)->unkC;
    if (newY > maxY)
    {
        ((GameObject*)obj)->anim.localPosY = maxY;
    }
    else
    {
        ((GameObject*)obj)->anim.localPosY = newY;
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
        if (((GameObject*)obj)->unkF4 <= 0)
        {
            ((GameObject*)obj)->unkF4 = randomGetRange(0x3c, 0xf0);
            if (lbl_803E4F84 == dist)
            {
                ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                    ((GameObject*)obj)->anim.localPosX,
                    ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, 0, lbl_803E4F88, 3);
            }
        }
    }
    return;
}

void mmsh_waterspike_init(int obj, s16* def)
{
    register u32 packedEventIds;
    register u32 lowEventId;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->unkF4 = 0;
    packedEventIds = (u32)(u16)((MmshWaterspikeObjectDef*)def)->unk1C << 16;
    lowEventId = (u32)(u16)((MmshWaterspikeObjectDef*)def)->unk1A;
    packedEventIds |= lowEventId;
    *(u32*)&((GameObject*)obj)->unkF8 = packedEventIds;
}

extern f32 lbl_803E4F78;
extern u8 Obj_IsLoadingLocked(void);
extern u8* Obj_AllocObjectSetup(int size, int type);
extern u8* Obj_SetupObject(u8* no, int a, int b, int c, int d);

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
