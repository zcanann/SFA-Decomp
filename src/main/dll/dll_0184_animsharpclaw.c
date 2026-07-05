/*
 * animsharpclaw (DLL 0x184) - an anim/sequence object (object type id 0xb).
 *
 * init wires the object's anim/trigger state (slot 0x64), records the
 * sequence id from placement, and either loads or reloads its anim data
 * depending on the placement variant byte. Each update ticks the object
 * trigger interface, services anim sequence events (fn_801A8F88: event 1
 * spawns a child setup object 0x30B and attaches it, event 2 detaches and
 * frees the child), then - once the object reaches the terminal sequence
 * index (-2) - scans the live object list for the matching sequence kind
 * and ends the shared trigger sequence when this is the last participant.
 * free detaches/frees the child, releases trigger state, drives the title-
 * menu control vtable slot 2, and stops the object's sfx channel.
 */
#include "main/objanim_update.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct AnimsharpclawPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 linkIndex;
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} AnimsharpclawPlacement;

typedef struct AnimsharpclawState
{
    u8 pad0[0x24 - 0x0];
    f32 dampingFactor; /* 0x24: base/(base + placement[0x24]) smoothing coefficient */
    s32 unk28;
    u8 pad2C[0x57 - 0x2C];
    u8 kind;
    u8 pad58[0x6A - 0x58];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x94 - 0x70];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0x140 - 0x9C];
} AnimsharpclawState;

extern void ObjLink_DetachChild(int obj, int child);
extern void ObjLink_AttachChild(int parent, int child, u16 linkMode);
extern int* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int allocResult, int a, int b, int c, int d);
extern void objSetSlot(void* obj, int slot);
extern u8 framesThisStep;

/* child setup-object id spawned on anim sequence event 1 */
#define ANIMSHARPCLAW_CHILD_SETUP_ID 0x30B

int fn_801A8F88(int obj, ObjAnimUpdateState* animUpdate);

#pragma scheduling off
#pragma dont_inline on
int fn_801A8F88(int obj, ObjAnimUpdateState* animUpdate)
{
    int i;
    int child;
    int alloc;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 v = animUpdate->eventIds[i];
        switch (v)
        {
        case 1:
            ((GameObject*)obj)->unkF8 = ANIMSHARPCLAW_CHILD_SETUP_ID;
            child = (int)((GameObject*)obj)->childObjs[0];
            if ((void*)child != NULL)
            {
                ObjLink_DetachChild(obj, child);
                Obj_FreeObject(child);
            }
            alloc = Obj_AllocObjectSetup(32, ((GameObject*)obj)->unkF8);
            alloc = Obj_SetupObject(alloc, 4, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                    *(int*)&((GameObject*)obj)->anim.parent);
            ObjLink_AttachChild(obj, alloc, 0);
            break;
        case 2:
            child = (int)((GameObject*)obj)->childObjs[0];
            if ((void*)child != NULL)
            {
                ObjLink_DetachChild(obj, child);
                Obj_FreeObject(child);
            }
            ((GameObject*)obj)->unkF8 = -1;
            break;
        }
    }
    return 0;
}
#pragma dont_inline reset
#pragma scheduling on

int animsharpclaw_getExtraSize(void) { return sizeof(AnimsharpclawState); }
int animsharpclaw_getObjectTypeId(void) { return 0xb; }

#pragma peephole off
#pragma scheduling off
void animsharpclaw_free(int obj)
{
    u8* inner;
    int child;
    inner = ((GameObject*)obj)->extra;
    child = (int)((GameObject*)obj)->childObjs[0];
    if ((void*)child != NULL)
    {
        ObjLink_DetachChild(obj, child);
        Obj_FreeObject(child);
    }
    (*gObjectTriggerInterface)->freeState(inner);
    (*(void (*)(int, int, int, int, int))(*(int*)(*gTitleMenuControlInterface + 0x8)))(obj, 0xffff, 0, 0, 0);
    Sfx_StopObjectChannel(obj, 0x7f);
}
#pragma scheduling on

void animsharpclaw_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, 1.0f);
}
#pragma peephole on

void animsharpclaw_hitDetect(void)
{
}

#pragma peephole off
#pragma scheduling off
void animsharpclaw_update(int* obj)
{
    int* placement;
    int kind;
    int kind2;
    int matchCount;
    int* objects;
    int* inner;
    int found;
    int i;
    int count;

    inner = ((GameObject*)obj)->extra;
    placement = *(int**)&((GameObject*)obj)->anim.placementData;
    if ((placement != NULL) && (((AnimsharpclawPlacement*)placement)->linkIndex != -1))
    {
        i = (*gObjectTriggerInterface)->update((u8*)obj, (f32)(u32)framesThisStep);
        fn_801A8F88((int)obj, (ObjAnimUpdateState*)inner);
        if ((i != 0) && (((GameObject*)obj)->seqIndex == -2))
        {
            kind = *(s8*)&((AnimsharpclawState*)inner)->kind;
            found = 0;
            objects = (int*)ObjList_GetObjects(&i, &count);
            matchCount = 0;
            for (i = 0, kind2 = (int)(s8)kind; i < count; i++)
            {
                int o = *objects;
                if (((GameObject*)o)->seqIndex == kind)
                {
                    found = o;
                }
                if (((GameObject*)o)->seqIndex == -2 && ((GameObject*)o)->anim.classId == 0x10 &&
                    kind2 == *(s8*)((char*)*(int**)&((GameObject*)o)->extra + 0x57))
                {
                    matchCount++;
                }
                objects = objects + 1;
            }
            if (matchCount <= 1 && (u32)found != 0 && ((GameObject*)found)->seqIndex != -1)
            {
                ((GameObject*)found)->seqIndex = -1;
                (*gObjectTriggerInterface)->endSequence(kind2);
            }
            ((GameObject*)obj)->seqIndex = -1;
        }
    }
}

void animsharpclaw_init(int* obj, u8* init)
{
    int* inner;
    int f4;

    ((GameObject*)obj)->animEventCallback = NULL;
    objSetSlot(obj, 0x64);
    inner = ((GameObject*)obj)->extra;
    ((AnimsharpclawState*)inner)->unk6A = ((AnimsharpclawPlacement*)init)->unk1A;
    ((AnimsharpclawState*)inner)->unk6E = -1;
    ((AnimsharpclawState*)inner)->dampingFactor = 1.0f / (1.0f + (f32)(u32)init[0x24]);
    ((AnimsharpclawState*)inner)->unk28 = -1;
    ((AnimsharpclawState*)inner)->unk98 = 0;
    ((AnimsharpclawState*)inner)->unk94 = 0;
    ((GameObject*)obj)->unkF8 = -1;
    f4 = ((GameObject*)obj)->unkF4;
    if (f4 == 0 && ((AnimsharpclawPlacement*)init)->linkIndex != 1)
    {
        (*gObjectTriggerInterface)->loadAnimData((u8*)inner, init);
        ((GameObject*)obj)->unkF4 = ((AnimsharpclawPlacement*)init)->linkIndex + 1;
    }
    else if (f4 != 0 && ((AnimsharpclawPlacement*)init)->linkIndex != f4 - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)inner);
        if (((AnimsharpclawPlacement*)init)->linkIndex != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)inner, init);
        }
        ((GameObject*)obj)->unkF4 = ((AnimsharpclawPlacement*)init)->linkIndex + 1;
    }
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->shadowTintA = 0x64;
        ((GameObject*)obj)->anim.modelState->shadowTintB = 0x96;
    }
}
#pragma peephole on
#pragma scheduling on

void animsharpclaw_release(void)
{
}

void animsharpclaw_initialise(void)
{
}
