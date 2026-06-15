#include "main/dll/DIM/dimlogfire.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct AnimsharpclawPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    u8 pad1A[0x20 - 0x1A];
} AnimsharpclawPlacement;

typedef struct AnimsharpclawState
{
    u8 pad0[0x24 - 0x0];
    f32 unk24;
    s32 unk28;
    u8 pad2C[0x57 - 0x2C];
    u8 unk57;
    u8 pad58[0x6A - 0x58];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x94 - 0x70];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0x140 - 0x9C];
} AnimsharpclawState;

extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803ad590;
extern undefined4 DAT_803ad598;
extern undefined4 DAT_803ad59c;
extern undefined4 DAT_803ad5a0;
extern undefined4 DAT_803ad5a4;
extern int* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern f32 lbl_803DC074;
extern f32 lbl_803E5248;
extern f32 lbl_803E524C;

extern f32 lbl_803E45C8;
extern void objRenderFn_8003b8f4(f32);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int allocResult, int a, int b, int c, int d);
extern f32 lbl_803E4610;
extern void objSetSlot(void* obj, int slot);
extern u8 framesThisStep;

void FUN_801a8f88(void)
{
    int iVar1;
    uint uVar2;
    short* psVar3;

    iVar1 = FUN_80286840();
    psVar3 = *(short**)(iVar1 + 0xb8);
    if (((int)*psVar3 == 0xffffffff) || (uVar2 = GameBit_Get((int)*psVar3), uVar2 != 0))
    {
        *(float*)(psVar3 + 0x14) = *(float*)(psVar3 + 0x14) - lbl_803DC074;
        if (*(float*)(psVar3 + 0x14) < lbl_803E5248)
        {
            *(float*)(psVar3 + 0xc) = lbl_803E524C;
            uVar2 = randomGetRange(-(uint)(ushort)psVar3[1], (uint)(ushort)psVar3[1]);
            *(float*)(psVar3 + 0xe) =
                (f32)(s32)(uVar2);
            uVar2 = randomGetRange(-(uint)(ushort)psVar3[3], (uint)(ushort)psVar3[3]);
            *(float*)(psVar3 + 0x10) =
                (f32)(s32)(uVar2);
            uVar2 = randomGetRange(-(uint)(ushort)psVar3[2], (uint)(ushort)psVar3[2]);
            *(float*)(psVar3 + 0x12) =
                (f32)(s32)(uVar2);
            FUN_80017748((ushort*)(psVar3 + 4), (float*)(psVar3 + 0xe));
            *(float*)(psVar3 + 0xe) = *(float*)(psVar3 + 0xe) + *(float*)(iVar1 + 0xc);
            *(float*)(psVar3 + 0x10) = *(float*)(psVar3 + 0x10) + *(float*)(iVar1 + 0x10);
            *(float*)(psVar3 + 0x12) = *(float*)(psVar3 + 0x12) + *(float*)(iVar1 + 0x14);
            uVar2 = randomGetRange(100, 200);
            *(float*)(psVar3 + 0x14) =
                (f32)(s32)(uVar2);
            uVar2 = randomGetRange(0x32, 100);
            *(float*)(psVar3 + 0x16) =
                (f32)(s32)(uVar2);
        }
        *(float*)(psVar3 + 0x16) = *(float*)(psVar3 + 0x16) - lbl_803DC074;
        if (lbl_803E5248 < *(float*)(psVar3 + 0x16))
        {
            (*gPartfxInterface)->spawnObject((void*)iVar1, 0x71f, psVar3 + 8, 0x200001, -1, NULL);
        }
        DAT_803ad598 = lbl_803E524C;
        uVar2 = randomGetRange(-(uint)(ushort)psVar3[1], (uint)(ushort)psVar3[1]);
        DAT_803ad59c = (f32)(s32)(uVar2);
        uVar2 = randomGetRange(-(uint)(ushort)psVar3[3], (uint)(ushort)psVar3[3]);
        DAT_803ad5a0 = (f32)(s32)(uVar2);
        uVar2 = randomGetRange(-(uint)(ushort)psVar3[2], (uint)(ushort)psVar3[2]);
        DAT_803ad5a4 = (f32)(s32)(uVar2);
        FUN_80017748((ushort*)(psVar3 + 4), &DAT_803ad59c);
        DAT_803ad59c = DAT_803ad59c + *(float*)(iVar1 + 0xc);
        DAT_803ad5a0 = DAT_803ad5a0 + *(float*)(iVar1 + 0x10);
        DAT_803ad5a4 = DAT_803ad5a4 + *(float*)(iVar1 + 0x14);
        (*gPartfxInterface)->spawnObject((void*)iVar1, 0x720, &DAT_803ad590, 0x200001, -1, NULL);
    }
    FUN_8028688c();
    return;
}

undefined4
FUN_801a9408(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             ObjAnimUpdateState* animUpdate)
{
    byte bVar1;
    undefined2* puVar2;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int iVar3;
    int iVar4;
    undefined8 uVar5;

    for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1)
    {
        bVar1 = animUpdate->eventIds[iVar3];
        if (bVar1 == 2)
        {
            iVar4 = *(int*)&((GameObject*)param_9)->childObjs[0];
            if (iVar4 != 0)
            {
                uVar5 = ObjLink_DetachChild(param_9, iVar4);
                param_1 = FUN_80017ac8(uVar5, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4);
            }
            *(undefined4*)(param_9 + 0xf8) = 0xffffffff;
        }
        else if ((bVar1 < 2) && (bVar1 != 0))
        {
            *(undefined4*)(param_9 + 0xf8) = 0x30b;
            iVar4 = *(int*)&((GameObject*)param_9)->childObjs[0];
            if (iVar4 != 0)
            {
                uVar5 = ObjLink_DetachChild(param_9, iVar4);
                param_1 = FUN_80017ac8(uVar5, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4);
            }
            puVar2 = FUN_80017aa4(0x20, (short)*(undefined4*)(param_9 + 0xf8));
            iVar4 = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, puVar2, 4,
                                 ((GameObject*)param_9)->anim.mapEventSlot, 0xffffffff,
                                 *(uint**)&((GameObject*)param_9)->anim.parent,
                                 in_r8, in_r9, in_r10);
            param_1 = ObjLink_AttachChild(param_9, iVar4, 0);
        }
    }
    return 0;
}

void animsharpclaw_hitDetect(void)
{
}

void animsharpclaw_release(void)
{
}

void animsharpclaw_initialise(void)
{
}

void MoonSeedPlantingSpot_hitDetect(void);

int animsharpclaw_getExtraSize(void) { return 0x140; }
int animsharpclaw_getObjectTypeId(void) { return 0xb; }
int MoonSeedPlantingSpot_render2(void);

#pragma peephole off
void animsharpclaw_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E45C8);
}

void ccgasventcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#pragma scheduling off
void animsharpclaw_free(int obj)
{
    char* inner;
    int* child;
    child = ((GameObject*)obj)->childObjs[0];
    inner = ((GameObject*)obj)->extra;
    if (child != NULL)
    {
        ObjLink_DetachChild(obj, (int)child);
        Obj_FreeObject((int)child);
    }
    (*gObjectTriggerInterface)->freeState((u8*)inner);
    (*(void (*)(int, int, int, int, int))(*(int*)(*gTitleMenuControlInterface + 0x8)))(obj, 0xffff, 0, 0, 0);
    Sfx_StopObjectChannel(obj, 0x7f);
}

#pragma dont_inline on
#pragma peephole on
int fn_801A8F88(int obj, ObjAnimUpdateState* animUpdate)
{
    int i;
    int state;
    int alloc;
    for (i = 0; i < (int)animUpdate->eventCount; i++)
    {
        u8 v = animUpdate->eventIds[i];
        switch (v)
        {
        case 1:
            ((GameObject*)obj)->unkF8 = 779;
            state = (int)((GameObject*)obj)->childObjs[0];
            if ((void*)state != NULL)
            {
                ObjLink_DetachChild(obj, state);
                Obj_FreeObject(state);
            }
            alloc = Obj_AllocObjectSetup(32, ((GameObject*)obj)->unkF8);
            alloc = Obj_SetupObject(alloc, 4, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                    *(int*)&((GameObject*)obj)->anim.parent);
            ObjLink_AttachChild(obj, alloc, 0);
            break;
        case 2:
            state = (int)((GameObject*)obj)->childObjs[0];
            if ((void*)state != NULL)
            {
                ObjLink_DetachChild(obj, state);
                Obj_FreeObject(state);
            }
            ((GameObject*)obj)->unkF8 = -1;
            break;
        }
    }
    return 0;
}
#pragma dont_inline reset

#pragma peephole off
void animsharpclaw_init(int* obj, u8* init)
{
    int* inner;
    int f4;

    ((GameObject*)obj)->animEventCallback = NULL;
    objSetSlot(obj, 0x64);
    inner = ((GameObject*)obj)->extra;
    ((AnimsharpclawState*)inner)->unk6A = *(s16*)((char*)init + 0x1a);
    ((AnimsharpclawState*)inner)->unk6E = -1;
    ((AnimsharpclawState*)inner)->unk24 = lbl_803E45C8 / (lbl_803E45C8 + (f32)(u32)
    init[0x24]
    )
    ;
    ((AnimsharpclawState*)inner)->unk28 = -1;
    ((AnimsharpclawState*)inner)->unk98 = 0;
    ((AnimsharpclawState*)inner)->unk94 = 0;
    ((GameObject*)obj)->unkF8 = -1;
    f4 = ((GameObject*)obj)->unkF4;
    if (f4 == 0 && *(s16*)((char*)init + 0x18) != 1)
    {
        (*gObjectTriggerInterface)->loadAnimData((u8*)inner, init);
        ((GameObject*)obj)->unkF4 = *(s16*)((char*)init + 0x18) + 1;
    }
    else if (f4 != 0 && *(s16*)((char*)init + 0x18) != f4 - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)inner);
        if (*(s16*)((char*)init + 0x18) != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)inner, init);
        }
        ((GameObject*)obj)->unkF4 = *(s16*)((char*)init + 0x18) + 1;
    }
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->shadowTintA = 0x64;
        ((GameObject*)obj)->anim.modelState->shadowTintB = 0x96;
    }
}

void animsharpclaw_update(int* obj)
{
    int* found;
    int* inner;
    int* child;
    int kind;
    int matchCount;
    int* objects;
    int i;
    int count;
    int result;

    inner = ((GameObject*)obj)->extra;
    child = *(int**)&((GameObject*)obj)->anim.placementData;
    if (child == NULL)
    {
        return;
    }
    if (((AnimsharpclawPlacement*)child)->unk18 == -1)
    {
        return;
    }
    {
        volatile int vres = (*gObjectTriggerInterface)->update((u8*)obj, (f32)(u32)framesThisStep);
        fn_801A8F88((int)obj, (ObjAnimUpdateState*)inner);
        if (vres == 0)
        {
            return;
        }
    }
    if (((GameObject*)obj)->seqIndex != -2)
    {
        return;
    }
    kind = (s8)((AnimsharpclawState*)inner)->unk57;
    found = NULL;
    objects = (int*)ObjList_GetObjects(&i, &count);
    matchCount = 0;
    for (i = 0; i < count; i++)
    {
        int* o = (int*)objects[i];
        if (((GameObject*)o)->seqIndex == kind)
        {
            found = o;
        }
        if (((GameObject*)o)->seqIndex == -2 && ((GameObject*)o)->anim.classId == 0x10 &&
            kind == (s8) * (u8*)((char*)*(int**)&((GameObject*)o)->extra + 0x57))
        {
            matchCount++;
        }
    }
    if (matchCount <= 1 && found != NULL && ((GameObject*)found)->seqIndex != -1)
    {
        ((GameObject*)found)->seqIndex = -1;
        (*gObjectTriggerInterface)->endSequence(kind);
    }
    ((GameObject*)obj)->seqIndex = -1;
}
