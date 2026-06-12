/*
 * wmcolumn (DLL 0x0116) - the carryable WM column. TU: 0x8017D37C-0x8017D818
 * (wm_column_* only; .text-only split, the descriptors live in the auto data
 * unit).
 *
 * NOTE: everything below the descriptors (FUN_8017db40, FUN_8017de58,
 * FUN_8017e15c, FUN_8017e3c0 + gAppleOnTreeObjDescriptor/jumptable_803214DC)
 * is v1.1-drift appleontree content in dll_0117's address range
 * (0x8017D818-0x8017EC10). The bodies are dead weight here (never linked,
 * never scored) but dll_0117_appleontree.c still references the FUN_ names
 * at its unmatched call sites, so they stay until that unit's recovery maps
 * them onto fn_8017D854 / appleontree_handleCollectableHit / fn_8017DCD4 /
 * fn_8017DF34.
 */
#include "main/dll/appleontreestate_struct.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);
extern undefined8 ObjGroup_RemoveObject();

extern ObjectTriggerInterface** gObjectTriggerInterface;

#include "main/dll/groundanimator_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/groundAnimator.h"
#include "main/game_object.h"

typedef struct WmColumnPlacement
{
    u8 pad0[0x18 - 0x0];
    u8 rotXByte;    /* 0x18: rotX in 1/256 turns */
    u8 modelIndex;  /* 0x19: bank index; the column variant's seqId is
                       500 + modelIndex (500 = retail type 'GPSHpickobj',
                       this DLL; 499 = its 'GPSH_Scene' spot object) */
    u8 pad1A[0x1E - 0x1A];
    s16 gameBit;    /* 0x1E: set while this column sits on its scene
                       spot, -1 = none */
    u8 pad20[0x38 - 0x20];
    u8 unk38;
    u8 unk39;
    u8 unk3A;
    u8 unk3B;
    s16 unk3C;
    u8 pad3E[0x40 - 0x3E];
} WmColumnPlacement;

STATIC_ASSERT(offsetof(WmColumnPlacement, gameBit) == 0x1E);

extern undefined8 FUN_80006824();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_800632d8();
extern undefined4 FUN_80081118();
extern double FUN_80293900();
extern undefined4 FUN_80294d60();
extern void GameBit_Set(int eventId, int value);
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern f32 Vec_distance(float* posA, float* posB);
extern int Obj_GetPlayerObject(void);
extern uint playerGetStateFlag310(int obj);
extern void setAButtonIcon(int param_1);

extern undefined4* DAT_803dd718;
extern f32 lbl_803DC074;
extern f32 lbl_803E37B8; /* 1.0: render scale */
extern f32 lbl_803E37BC; /* 10000.0: nearest-object sentinel */
extern f32 lbl_803E37C0; /* 35.0: scene-spot snap radius */
extern f32 lbl_803E37C4; /* 60.0: pickup prompt distance */
extern f32 lbl_803E4460;
extern f32 lbl_803E446C;
extern f32 lbl_803E4470;
extern f32 lbl_803E4474;
extern f32 lbl_803E4478;
extern f32 lbl_803E447C;
extern f32 lbl_803E4480;
extern f32 lbl_803E4484;
extern f32 lbl_803E4488;
extern f32 lbl_803E448C;
extern f32 lbl_803E4490;
extern f32 lbl_803E4494;
extern f32 lbl_803E4498;

typedef void (*GroundAnimatorFreeFn)(int obj);
typedef int (*GroundAnimatorVisibleFn)(int obj, int visible);
typedef int (*GroundAnimatorAnimStateFn)(int obj, int state);
typedef void (*GroundAnimatorSetVisibleFn)(int state, int visible);
typedef void (*GroundAnimatorInitAnimFn)(void* obj, undefined4 state, int arg);

/* the carryable/groundAnimator interface vtable (gCarryableInterface) */
typedef struct CarryableInterface
{
    u8 pad00[4];
    GroundAnimatorInitAnimFn initAnim;      /* 0x04 */
    GroundAnimatorAnimStateFn getAnimState; /* 0x08: nonzero while held */
    GroundAnimatorVisibleFn isVisible;      /* 0x0C */
    GroundAnimatorFreeFn free;              /* 0x10 */
    u8 pad14[0x24 - 0x14];
    GroundAnimatorSetVisibleFn setVisible;  /* 0x24 */
} CarryableInterface;

STATIC_ASSERT(offsetof(CarryableInterface, setVisible) == 0x24);

extern CarryableInterface** gCarryableInterface;

extern void appleontree_init();
extern void appleontree_update();
extern void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
extern void appleontree_free(int* obj);
extern int appleontree_getExtraSize(void);
extern void appleontree_setScale(void);
extern u8 appleontree_modelMtxFn(int* obj);
STATIC_ASSERT(offsetof(AppleOnTreeState, healthRestore) == 0x38);
STATIC_ASSERT(offsetof(AppleOnTreeState, unk50) == 0x50);
STATIC_ASSERT(offsetof(AppleOnTreeState, unk60) == 0x60);
STATIC_ASSERT(sizeof(AppleOnTreeState) == 0x64);
extern f32 Vec_xzDistance(float* a, float* b);

int wm_column_getExtraSize(void)
{
    return 0xa;
}

int wm_column_getObjectTypeId(void)
{
    return 0;
}

void wm_column_free(int obj)
{
    ObjGroup_RemoveObject(obj, 4);
    (*gCarryableInterface)->free(obj);
}

void wm_column_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    extern void objRenderFn_8003b8f4(int param_1, int param_2, int param_3, int param_4, int param_5, f32 scale); /* #57 */
    if ((*gCarryableInterface)->isVisible(param_1, visible) != 0)
    {
        objRenderFn_8003b8f4(param_1, param_2, param_3, param_4, param_5, lbl_803E37B8);
    }
}

void wm_column_hitDetect(void)
{
}

void wm_column_update(int obj)
{
    int* objects;
    u32 playerFlags;
    f32 nearest;
    int i;
    int count;
    int other;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    nearest = lbl_803E37BC;
    if ((*gCarryableInterface)->getAnimState(obj, *(int*)&((GameObject*)obj)->extra) != 0)
    {
        if ((((GameObject*)obj)->unkF4 & 2) != 0)
        {
            objects = ObjList_GetObjects(&i, &count);
            for (; i < count; i++)
            {
                other = objects[i];
                if (((u32)other != (u32)obj) && (((GameObject*)other)->anim.seqId == 499) &&
                    (Vec_distance((float*)(obj + 0x18), (float*)(other + 0x18)) < lbl_803E37C0))
                {
                    other = ((WmColumnPlacement*)((GameObject*)objects[i])->anim.placement)->gameBit;
                    if (other != -1)
                    {
                        GameBit_Set(other, 0);
                    }
                }
            }
        }
        playerFlags = Obj_GetPlayerObject();
        ObjGroup_FindNearestObject(0x10, obj, &nearest);
        playerFlags = playerGetStateFlag310(playerFlags);
        if (((playerFlags & 0x4000) != 0) && (nearest > lbl_803E37C4))
        {
            (*gCarryableInterface)->setVisible(state, 0);
            setAButtonIcon(5);
            *(u32*)&((GameObject*)obj)->unkF4 |= 1;
        }
        else
        {
            (*gCarryableInterface)->setVisible(state, 1);
        }
        *(u32*)&((GameObject*)obj)->unkF4 &= ~2;
    }
    else
    {
        if ((((GameObject*)obj)->unkF4 & 1) != 0)
        {
            objects = ObjList_GetObjects(&i, &count);
            for (; i < count; i++)
            {
                other = objects[i];
                if (((u32)other != (u32)obj) && (((GameObject*)other)->anim.seqId == 499) &&
                    (Vec_distance((float*)(obj + 0x18), (float*)(other + 0x18)) < lbl_803E37C0))
                {
                    int mapData = *(int*)&((GameObject*)objects[i])->anim.placementData;
                    if (((GameObject*)obj)->anim.seqId == (s8)((WmColumnPlacement*)mapData)->modelIndex + 500)
                    {
                        if (((WmColumnPlacement*)mapData)->gameBit != -1)
                        {
                            GameBit_Set(((WmColumnPlacement*)mapData)->gameBit, 1);
                        }
                    }
                    else if (((WmColumnPlacement*)mapData)->gameBit != -1)
                    {
                        GameBit_Set(((WmColumnPlacement*)mapData)->gameBit, 0);
                    }
                    ((GameObject*)obj)->anim.localPosX = ((GameObject*)objects[i])->anim.localPosX;
                    ((GameObject*)obj)->anim.localPosY = ((GameObject*)objects[i])->anim.localPosY;
                    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)objects[i])->anim.localPosZ;
                }
            }
        }
        playerFlags = playerGetStateFlag310(Obj_GetPlayerObject());
        if ((playerFlags & 0x4000) != 0)
        {
            (*gCarryableInterface)->setVisible(state, 0);
            *(u32*)&((GameObject*)obj)->unkF4 |= 2;
        }
        else
        {
            (*gCarryableInterface)->setVisible(state, 1);
            *(u32*)&((GameObject*)obj)->unkF4 &= ~2;
        }
        *(u32*)&((GameObject*)obj)->unkF4 &= ~1;
    }
}

void wm_column_init(GameObject* obj, WmColumnPlacement* mapData)
{
    int state = *(int*)&obj->extra;
    obj->anim.rotX = (s16)(mapData->rotXByte << 8);
    obj->objectFlags |= 0x2000;
    obj->unkF4 = 0;
    obj->anim.bankIndex = (s8)mapData->modelIndex;
    if (obj->anim.bankIndex >= obj->anim.modelInstance->modelCount)
    {
        obj->anim.bankIndex = 0;
    }
    (*gCarryableInterface)->initAnim(obj, state, 0x32);
    ObjGroup_AddObject((int)obj, 4);
}

void wm_column_release(void)
{
}

void wm_column_initialise(void)
{
}

ObjectDescriptor gWM_ColumnObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wm_column_initialise,
    (ObjectDescriptorCallback)wm_column_release,
    0,
    (ObjectDescriptorCallback)wm_column_init,
    (ObjectDescriptorCallback)wm_column_update,
    (ObjectDescriptorCallback)wm_column_hitDetect,
    (ObjectDescriptorCallback)wm_column_render,
    (ObjectDescriptorCallback)wm_column_free,
    (ObjectDescriptorCallback)wm_column_getObjectTypeId,
    wm_column_getExtraSize,
};

ObjectDescriptor13 gAppleOnTreeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)appleontree_init,
    (ObjectDescriptorCallback)appleontree_update,
    0,
    (ObjectDescriptorCallback)appleontree_render,
    (ObjectDescriptorCallback)appleontree_free,
    0,
    appleontree_getExtraSize,
    (ObjectDescriptorCallback)appleontree_setScale,
    (ObjectDescriptorCallback)appleontree_func0B,
    (ObjectDescriptorCallback)appleontree_modelMtxFn,
};

u32 jumptable_803214DC[] = {
    (u32)((u8*)appleontree_update + 0x170),
    (u32)((u8*)appleontree_update + 0x274),
    (u32)((u8*)appleontree_update + 0x3C4),
    (u32)((u8*)appleontree_update + 0x4E8),
    (u32)((u8*)appleontree_update + 0x554),
    (u32)((u8*)appleontree_update + 0x6C8),
    (u32)((u8*)appleontree_update + 0x71C),
};

/* ---- v1.1-drift appleontree content (DLL 0x0117 range) from here
   down - see the header note. ---- */
#pragma scheduling on
#pragma peephole on
void FUN_8017db40(uint param_1, int param_2)
{
    undefined2 uVar1;
    uint uVar2;
    int iVar3;
    int iVar4;
    double dVar5;
    double dVar6;
    double dVar7;
    undefined8 in_f4;
    double dVar8;
    undefined8 in_f5;
    undefined8 in_f6;
    undefined8 in_f7;
    undefined8 in_f8;

    iVar4 = *(int*)&((GameObject*)param_1)->extra;
    if (param_2 == 1)
    {
        uVar1 = 2;
    }
    else
    {
        if (param_2 < 1)
        {
            if (-1 < param_2)
            {
                uVar1 = 2;
                goto LAB_8017de10;
            }
        }
        else if (param_2 < 3)
        {
            uVar1 = 2;
            goto LAB_8017de10;
        }
        uVar1 = 0;
    }
LAB_8017de10:
    *(undefined2*)(iVar4 + 0x38) = uVar1;
    *(u8*)(iVar4 + 0x3a) = 4;
    *(float*)&((GroundAnimatorState*)iVar4)->linkedObj = lbl_803DC074;
    ((GroundAnimatorState*)iVar4)->sinkDepth = lbl_803DC074;
    uVar2 = randomGetRange(0xffff8000, 0x7fff);
    *(short*)(iVar4 + 0x48) = (short)uVar2;
    uVar2 = randomGetRange(0xffff8000, 0x7fff);
    *(short*)(iVar4 + 0x4a) = (short)uVar2;
    *(undefined2*)(iVar4 + 0x4c) = 0x2000;
    dVar5 = (double)((GameObject*)param_1)->anim.localPosX;
    dVar6 = (double)((GameObject*)param_1)->anim.localPosY;
    dVar7 = (double)((GameObject*)param_1)->anim.localPosZ;
    iVar3 = FUN_800632d8(dVar5, dVar6, dVar7, param_1, (float*)(iVar4 + 0x30), 0);
    if (iVar3 == 0)
    {
        iVar4 = *(int*)&((GameObject*)param_1)->extra;
        if ((*(ushort*)&((GameObject*)param_1)->anim.flags & 0x2000) == 0)
        {
            if (*(int*)&((GameObject*)param_1)->anim.hitReactState != 0)
            {
                ObjHits_DisableObject(param_1);
            }
            *(byte*)(iVar4 + 0x5a) = *(byte*)(iVar4 + 0x5a) | 2;
        }
        else
        {
            FUN_80017ac8(dVar5, dVar6, dVar7, in_f4, in_f5, in_f6, in_f7, in_f8, param_1);
        }
    }
    else
    {
        dVar5 = (double)*(float*)(iVar4 + 0x40);
        dVar6 = FUN_80293900(-(double)((float)((double)lbl_803E4470 * dVar5) *
            *(float*)(iVar4 + 0x30) - lbl_803E446C));
        dVar7 = (double)(float)((double)lbl_803E4474 * dVar5);
        dVar5 = dVar7;
        if (dVar7 < (double)lbl_803E446C)
        {
            dVar5 = -dVar7;
        }
        if ((double)lbl_803E4478 < dVar5)
        {
            dVar8 = (double)(float)((double)(float)((double)lbl_803E447C - dVar6) / dVar7);
            dVar5 = (double)(float)((double)(float)((double)lbl_803E447C + dVar6) / dVar7);
            if ((double)lbl_803E446C < dVar8)
            {
                dVar5 = dVar8;
            }
        }
        else
        {
            dVar5 = (double)lbl_803E4460;
        }
        *(float*)(iVar4 + 0x50) = (float)dVar5;
        if (lbl_803E446C <= *(float*)(iVar4 + 0x28))
        {
            dVar6 = (double)lbl_803E4480;
            *(float*)(iVar4 + 0x30) =
                (float)(dVar6 * (double)(lbl_803E4470 * *(float*)(iVar4 + 0x24)) +
                    (double)*(float*)(iVar4 + 0x30));
        }
        else
        {
            dVar6 = (double)lbl_803E4470;
            *(float*)(iVar4 + 0x30) =
                -(float)(dVar6 * (double)*(float*)(iVar4 + 0x24) - (double)*(float*)(iVar4 + 0x30));
        }
        if ((double)lbl_803E446C < (double)*(float*)(iVar4 + 0x30))
        {
            *(undefined4*)(iVar4 + 0x2c) = *(undefined4*)(param_1 + 0x10);
            *(float*)(iVar4 + 0x34) = ((GameObject*)param_1)->anim.localPosY - *(float*)(iVar4 + 0x30);
            if (*(int*)&((GameObject*)param_1)->anim.hitReactState != 0)
            {
                ObjHits_DisableObject(param_1);
            }
            FUN_80006824(param_1, SFXen_bridge_stops);
        }
        else
        {
            iVar3 = *(int*)&((GameObject*)param_1)->extra;
            if ((*(ushort*)&((GameObject*)param_1)->anim.flags & 0x2000) == 0)
            {
                if (*(int*)&((GameObject*)param_1)->anim.hitReactState != 0)
                {
                    ObjHits_DisableObject(param_1);
                }
                *(byte*)(iVar3 + 0x5a) = *(byte*)(iVar3 + 0x5a) | 2;
            }
            else
            {
                FUN_80017ac8((double)*(float*)(iVar4 + 0x30), dVar6, dVar7, dVar5, in_f5, in_f6, in_f7, in_f8,
                             param_1);
            }
        }
    }
    return;
}

void FUN_8017de58(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    int iVar1;
    uint uVar2;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int iVar3;
    double dVar4;
    undefined8 uVar5;

    iVar3 = *(int*)&((GameObject*)param_9)->extra;
    iVar1 = FUN_80017a98();
    dVar4 = (double)FUN_80017710((float*)(iVar1 + 0x18), (float*)(param_9 + 0x18));
    if ((dVar4 < (double)lbl_803E4484) &&
        (dVar4 = (double)FUN_8001771c((float*)(iVar1 + 0x18), (float*)(param_9 + 0x18)),
            dVar4 < (double)lbl_803E4488))
    {
        uVar2 = GameBit_Get(0x90f);
        if (uVar2 == 0)
        {
            uVar5 = (*gObjectTriggerInterface)->setObjects(0x444, 0, 0);
            *(undefined2*)(iVar3 + 0x5c) = 0xffff;
            *(undefined2*)(iVar3 + 0x5e) = 0;
            *(float*)(iVar3 + 0x60) = lbl_803E4460;
            ObjMsg_SendToObject(uVar5, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar1, 0x7000a,
                                param_9, iVar3 + 0x5c, in_r7, in_r8, in_r9, in_r10);
            GameBit_Set(0x90f, 1);
            *(byte*)(iVar3 + 0x5a) = *(byte*)(iVar3 + 0x5a) | 4;
        }
        else
        {
            FUN_80294d60(dVar4, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar1,
                         (uint) * (ushort*)(iVar3 + 0x38));
            FUN_80081118((double)lbl_803E4460, param_9, 0xff, 0x28);
            uVar5 = FUN_80006824(param_9, SFXen_waterblock_stop);
            iVar1 = *(int*)&((GameObject*)param_9)->extra;
            if ((*(ushort*)&((GameObject*)param_9)->anim.flags & 0x2000) == 0)
            {
                if (*(int*)&((GameObject*)param_9)->anim.hitReactState != 0)
                {
                    ObjHits_DisableObject(param_9);
                }
                *(byte*)(iVar1 + 0x5a) = *(byte*)(iVar1 + 0x5a) | 2;
            }
            else
            {
                FUN_80017ac8(uVar5, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
            }
        }
    }
    return;
}

/* forward decl only - appleontree_handleCollectableHit (the
 * ground-animator collectable hit handler: trigger event on first
 * contact, else healing + particle FX + sfx + free-or-disable) is
 * FUN_8017de58's real name; see the header note. */
void appleontree_handleCollectableHit(int obj);

undefined4 FUN_8017e15c(double param_1, undefined2* param_2, int param_3)
{
    float fVar1;
    float fVar2;
    float fVar3;
    undefined4 uVar4;
    double dVar5;
    double dVar6;
    double dVar7;

    fVar1 = lbl_803E446C;
    dVar5 = (double)lbl_803E446C;
    dVar6 = (double)*(float*)(param_3 + 0x40);
    if (dVar5 == dVar6)
    {
        uVar4 = 1;
    }
    else
    {
        fVar2 = *(float*)(param_3 + 0x30);
        if (dVar5 <= (double)(fVar2 - (float)((double)*(float*)(param_3 + 0x2c) - param_1)))
        {
            *(float*)(param_2 + 8) = (float)param_1;
            uVar4 = 1;
        }
        else
        {
            dVar7 = (double)*(float*)(param_3 + 0x44);
            if (dVar5 == dVar7)
            {
                dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                    (double)((float)((double)lbl_803E4470 * dVar6) * fVar2
                    )));
                fVar1 = (float)((double)lbl_803E4474 * dVar6);
                fVar2 = fVar1;
                if (fVar1 < lbl_803E446C)
                {
                    fVar2 = -fVar1;
                }
                fVar3 = lbl_803E4460;
                if (lbl_803E4478 < fVar2)
                {
                    fVar2 = (float)(-dVar7 - dVar5) / fVar1;
                    fVar3 = (float)(-dVar7 + dVar5) / fVar1;
                    if (lbl_803E446C < fVar2)
                    {
                        fVar3 = fVar2;
                    }
                }
                *(float*)(param_3 + 0xc) = *(float*)(param_3 + 0xc) - fVar3;
                *(float*)(param_3 + 0x2c) = *(float*)(param_3 + 0x2c) - *(float*)(param_3 + 0x30);
                *(float*)(param_3 + 0x30) = lbl_803E446C;
                *(undefined4*)(param_2 + 8) = *(undefined4*)(param_3 + 0x2c);
                *param_2 = *(undefined2*)(param_3 + 0x48);
                param_2[1] = *(undefined2*)(param_3 + 0x4a);
                param_2[2] = *(undefined2*)(param_3 + 0x4c);
                *(float*)(param_3 + 0x44) = -*(float*)(param_3 + 0x28);
                if ((*(byte*)(param_3 + 0x5a) & 8) == 0)
                {
                    FUN_80006824((uint)param_2, 0x407);
                    *(byte*)(param_3 + 0x5a) = *(byte*)(param_3 + 0x5a) | 8;
                }
                uVar4 = 1;
            }
            else if ((double)lbl_803E448C <= dVar7)
            {
                dVar6 = (double)(float)(dVar6 + (double)*(float*)(param_3 + 0x3c));
                dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                    (double)((float)((double)lbl_803E4470 * dVar6) * fVar2
                    )));
                fVar1 = (float)((double)lbl_803E4474 * dVar6);
                fVar2 = fVar1;
                if (fVar1 < lbl_803E446C)
                {
                    fVar2 = -fVar1;
                }
                fVar3 = lbl_803E4460;
                if (lbl_803E4478 < fVar2)
                {
                    fVar2 = (float)(-dVar7 - dVar5) / fVar1;
                    fVar3 = (float)(-dVar7 + dVar5) / fVar1;
                    if (lbl_803E446C < fVar2)
                    {
                        fVar3 = fVar2;
                    }
                }
                *(float*)(param_3 + 0xc) = *(float*)(param_3 + 0xc) - fVar3;
                *(undefined4*)(param_2 + 8) = *(undefined4*)(param_3 + 0x2c);
                *(float*)(param_3 + 0x44) = *(float*)(param_3 + 0x44) * lbl_803E4490;
                uVar4 = 0;
            }
            else
            {
                *(float*)(param_2 + 8) = *(float*)(param_3 + 0x2c);
                *(float*)(param_3 + 0x40) = fVar1;
                *(float*)(param_3 + 0x44) = fVar1;
                uVar4 = 1;
            }
        }
    }
    return uVar4;
}

undefined4 FUN_8017e3c0(double param_1, undefined2* param_2, int param_3)
{
    float fVar1;
    float fVar2;
    float fVar3;
    undefined4 uVar4;
    double dVar5;
    double dVar6;
    double dVar7;

    if (lbl_803E446C == *(float*)(param_3 + 0x3c))
    {
        if (lbl_803E446C <
            *(float*)(param_3 + 0x30) - (float)((double)*(float*)(param_3 + 0x2c) - param_1))
        {
            *(float*)(param_2 + 8) = (float)param_1;
            uVar4 = 1;
        }
        else
        {
            dVar6 = (double)*(float*)(param_3 + 0x40);
            dVar7 = (double)*(float*)(param_3 + 0x44);
            dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                (double)((float)((double)lbl_803E4470 * dVar6) *
                    *(float*)(param_3 + 0x30))));
            fVar1 = (float)((double)lbl_803E4474 * dVar6);
            fVar2 = fVar1;
            if (fVar1 < lbl_803E446C)
            {
                fVar2 = -fVar1;
            }
            fVar3 = lbl_803E4460;
            if (lbl_803E4478 < fVar2)
            {
                fVar2 = (float)(-dVar7 - dVar5) / fVar1;
                fVar3 = (float)(-dVar7 + dVar5) / fVar1;
                if (lbl_803E446C < fVar2)
                {
                    fVar3 = fVar2;
                }
            }
            *(float*)(param_3 + 0xc) = *(float*)(param_3 + 0xc) - fVar3;
            *(float*)(param_3 + 0x2c) = *(float*)(param_3 + 0x2c) - *(float*)(param_3 + 0x30);
            *(float*)(param_3 + 0x30) = lbl_803E446C;
            *(undefined4*)(param_2 + 8) = *(undefined4*)(param_3 + 0x2c);
            *param_2 = *(undefined2*)(param_3 + 0x48);
            param_2[1] = *(undefined2*)(param_3 + 0x4a);
            param_2[2] = *(undefined2*)(param_3 + 0x4c);
            *(float*)(param_3 + 0x44) =
                lbl_803E4474 * *(float*)(param_3 + 0x40) * fVar3 + *(float*)(param_3 + 0x44);
            *(undefined4*)(param_3 + 0x3c) = *(undefined4*)(param_3 + 0x28);
            (**(code**)(*DAT_803dd718 + 0x10))
            ((double)*(float*)(param_2 + 6), (double)*(float*)(param_3 + 0x34),
             (double)*(float*)(param_2 + 10), param_2);
            uVar4 = 0;
        }
    }
    else if ((float)(param_1 - (double)*(float*)(param_3 + 0x2c)) < lbl_803E446C)
    {
        *(float*)(param_2 + 8) = (float)param_1;
        uVar4 = 1;
    }
    else
    {
        dVar7 = (double)(*(float*)(param_3 + 0x40) + *(float*)(param_3 + 0x3c));
        dVar6 = (double)*(float*)(param_3 + 0x44);
        dVar5 = FUN_80293900((double)(float)(dVar6 * dVar6 -
            (double)((float)((double)lbl_803E4470 * dVar7) *
                *(float*)(param_3 + 0x30))));
        fVar1 = (float)((double)lbl_803E4474 * dVar7);
        fVar2 = fVar1;
        if (fVar1 < lbl_803E446C)
        {
            fVar2 = -fVar1;
        }
        fVar3 = lbl_803E4460;
        if (lbl_803E4478 < fVar2)
        {
            fVar2 = (float)(-dVar6 - dVar5) / fVar1;
            fVar3 = (float)(-dVar6 + dVar5) / fVar1;
            if (lbl_803E446C < fVar2)
            {
                fVar3 = fVar2;
            }
        }
        *(float*)(param_3 + 0xc) = *(float*)(param_3 + 0xc) - fVar3;
        *(undefined4*)(param_2 + 8) = *(undefined4*)(param_3 + 0x2c);
        *(float*)(param_3 + 0x3c) = lbl_803E4494;
        *(float*)(param_3 + 0x44) = lbl_803E4498;
        uVar4 = 0;
    }
    return uVar4;
}

