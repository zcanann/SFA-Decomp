#include "main/obj_placement.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/scarab.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/objtexture.h"

extern undefined8 FUN_80003494();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80006a54();
extern undefined4 FUN_80017698();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017b00();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined8 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_8003b818();
extern double FUN_80293900();

extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3a58;
extern f32 lbl_803E3A60;
extern f32 lbl_803E3A64;
extern f32 lbl_803E3A68;
extern f32 lbl_803E3A6C;
extern f32 lbl_803E3A70;
extern f32 lbl_803E3A74;
extern f32 lbl_803E3A78;
extern f32 lbl_803E3A7C;
extern f32 lbl_803E3B00;
extern f32 lbl_803E3B04;
extern f32 lbl_803E3B08;
extern f32 lbl_803E3B0C;
extern f32 lbl_803E3B10;
extern f32 lbl_803E3B24;
extern f32 lbl_803E3B28;
extern f32 lbl_803E3B2C;
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B80;
extern f32 lbl_803E3B88;
extern f32 lbl_803E3B8C;
extern f32 lbl_803E3B90;
extern f32 lbl_803E3B94;

extern int Obj_GetPlayerObject(void);
extern f32 timeDelta;
extern uint GameBit_Get(int eventId);
extern int getAngle(f32 a, f32 b);
extern f32 lbl_803E2E30;
extern void objRenderFn_8003b8f4(f32);
extern void GameBit_Set(int eventId, int value);
extern f32 sqrtf(f32);

undefined4
FUN_8015e0d0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int param_10)
{
    float fVar1;
    float* pfVar2;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined8 uVar3;

    fVar1 = lbl_803E3A60;
    if (*(char*)(param_10 + 0x27b) == '\0')
    {
        if (*(char*)(param_10 + 0x346) != '\0')
        {
            uVar3 = ObjMsg_SendToObjects(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0, 3,
                                         param_9, 0xe0000, param_9, in_r8, in_r9, in_r10);
            if (*(int*)&((GameObject*)param_9)->anim.placementData == 0)
            {
                FUN_80017ac8(uVar3, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
                return 0;
            }
            return 4;
        }
    }
    else
    {
        pfVar2 = *(float**)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
        *pfVar2 = lbl_803E3A60;
        pfVar2[1] = fVar1;
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 6);
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(undefined*)(param_10 + 0x25f) = 0;
        *(undefined*)(param_10 + 0x349) = 0;
        ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
    }
    return 0;
}

int fn_8015E210(int* obj, GroundBaddieState* state);

undefined4
FUN_8015e2e0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float fVar1;
    int iVar2;
    int iVar3;
    double dVar4;

    iVar3 = *(int*)&((GameObject*)param_9)->extra;
    *(undefined*)(param_10 + 0x34d) = 3;
    *(float*)(param_10 + 0x2a0) = lbl_803E3A64;
    fVar1 = lbl_803E3A60;
    dVar4 = (double)lbl_803E3A60;
    *(float*)(param_10 + 0x280) = lbl_803E3A60;
    *(float*)(param_10 + 0x284) = fVar1;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8(dVar4, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9, 1, 0, param_12,
                     param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    if ((*(byte*)(param_10 + 0x356) & 1) == 0)
    {
        iVar2 = FUN_80017a98();
        if (*(short*)(iVar2 + 0x46) == 0)
        {
            FUN_80006824(param_9, SFXfox_treadwater322);
        }
        else
        {
            FUN_80006824(param_9, SFXfoot_metal_run_2);
        }
        FUN_80006824(param_9, SFXdoor_unlocked);
        FUN_80006824(param_9, SFXfoxcom_find);
        *(byte*)(param_10 + 0x356) = *(byte*)(param_10 + 0x356) | 1;
    }
    if (((*(byte*)(param_10 + 0x356) & 2) == 0) && (lbl_803E3A68 < ((GameObject*)param_9)->anim.currentMoveProgress))
    {
        FUN_80006824(param_9, SFXdoor_creak);
        *(byte*)(param_10 + 0x356) = *(byte*)(param_10 + 0x356) | 2;
        (**(code**)(*DAT_803dd738 + 0x4c))(param_9, (int)*(short*)(iVar3 + 0x3f0), 0xffffffff, 0);
    }
    return 0;
}

undefined4
FUN_8015e488(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    uint uVar2;
    int iVar3;
    int local_18;
    int local_14;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        iVar1 = FUN_80017b00(&local_18, &local_14);
        for (; local_18 < local_14; local_18 = local_18 + 1)
        {
            uVar2 = *(uint*)(iVar1 + local_18 * 4);
            if ((uVar2 != param_9) && (*(short*)(uVar2 + 0x46) == 0x306))
            {
                (**(code**)(**(int**)(uVar2 + 0x68) + 0x24))(uVar2, 0x81, 0);
            }
        }
        iVar1 = FUN_80017a98();
        iVar3 = *(int*)(iVar1 + 200);
        iVar1 = FUN_80017a98();
        iVar3 = (**(code**)(**(int**)(iVar3 + 0x68) + 0x44))(iVar3);
        if (iVar3 == 0)
        {
            if (*(short*)(iVar1 + 0x46) == 0)
            {
                FUN_80006824(param_9, SFXfox_treadwater322);
            }
            else
            {
                FUN_80006824(param_9, SFXfoot_metal_run_2);
            }
        }
        else if (*(short*)(iVar1 + 0x46) == 0)
        {
            FUN_80006824(param_9, SFXmv_ropecreak22);
        }
        else
        {
            FUN_80006824(param_9, SFXfoot_metal_run_2);
        }
        FUN_80006824(param_9, SFXfoxcom_stay);
    }
    *(undefined*)(param_10 + 0x34d) = 3;
    *(float*)(param_10 + 0x2a0) = lbl_803E3A6C;
    *(float*)(param_10 + 0x280) = lbl_803E3A60;
    return 0;
}

int fn_8015DC04(int obj, GroundBaddieState* p);

undefined4
FUN_8015e678(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    uint uVar2;
    int iVar3;
    int iVar4;
    int local_18;
    int local_14;
    ObjHitsPriorityState* hitState;

    iVar4 = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    iVar3 = -1;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        iVar1 = FUN_80017b00(&local_18, &local_14);
        for (; local_18 < local_14; local_18 = local_18 + 1)
        {
            uVar2 = *(uint*)(iVar1 + local_18 * 4);
            if ((uVar2 != param_9) && (*(short*)(uVar2 + 0x46) == 0x306))
            {
                iVar3 = **(int**)(uVar2 + 0x68);
                (**(code**)(iVar3 + 0x24))(uVar2, 0x81, 0);
            }
        }
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3A70;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, iVar3, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        iVar4 = *(int*)(iVar4 + 0x40c);
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
        *(byte*)(iVar4 + 8) = *(byte*)(iVar4 + 8) | 1;
        FUN_80006824(param_9, SFXfoxcom_heel);
    }
    return 0;
}

undefined4
FUN_8015e88c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 uVar1;
    ObjHitsPriorityState* hitState;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar1 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    *(float*)(param_10 + 0x2a0) = lbl_803E3A70;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, uVar1, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    return 0;
}

undefined4
FUN_8015e9f4(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    int iVar2;
    uint uVar3;
    int iVar4;
    int iVar5;
    int local_28;
    int local_24[5];
    ObjHitsPriorityState* hitState;

    iVar5 = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    iVar4 = -1;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        iVar1 = FUN_80017b00(&local_28, local_24);
        for (; local_28 < local_24[0]; local_28 = local_28 + 1)
        {
            iVar2 = *(int*)(iVar1 + local_28 * 4);
            if ((iVar2 != param_9) && (*(short*)(iVar2 + 0x46) == 0x306))
            {
                iVar4 = **(int**)(iVar2 + 0x68);
                (**(code**)(iVar4 + 0x24))(iVar2, 0x81, 0);
            }
        }
        uVar3 = randomGetRange(0, 1);
        if (uVar3 == 0)
        {
            if (*(char*)(param_10 + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, iVar4, param_13, param_14, param_15, param_16);
                *(undefined*)(param_10 + 0x346) = 0;
            }
        }
        else if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, iVar4, param_13, param_14, param_15, param_16);
            *(undefined*)(param_10 + 0x346) = 0;
        }
        *(undefined*)(param_10 + 0x34d) = 1;
        *(float*)(param_10 + 0x2a0) =
            lbl_803E3A74 +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(iVar5 + 0x406)) - DOUBLE_803e3a58) /
            lbl_803E3A78;
    }
    *(float*)(param_10 + 0x280) = lbl_803E3A60;
    return 0;
}

void fn_8015EB6C(int obj, int p2, int p3);

undefined4
FUN_8015ec98(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int unaff_r29;
    int iVar1;

    iVar1 = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0xe, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    if (lbl_803E3A7C < ((GameObject*)param_9)->anim.currentMoveProgress)
    {
        unaff_r29 = *(int*)(iVar1 + 0x40c);
        *(byte*)(unaff_r29 + 8) = *(byte*)(unaff_r29 + 8) | 2;
    }
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_DisableObject(param_9);
        *(float*)(param_10 + 0x2a0) = lbl_803E3A70;
        *(float*)(param_10 + 0x280) = lbl_803E3A60;
    }
    if (*(char*)(param_10 + 0x346) != '\0')
    {
        FUN_80017698((int)*(short*)(iVar1 + 0x3f4), 0);
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(undefined*)(param_10 + 0x25f) = 0;
        *(undefined*)(param_10 + 0x349) = 0;
        *(undefined2*)(iVar1 + 0x402) = 0;
        if ((*(byte*)(unaff_r29 + 9) & 2) == 0)
        {
            *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.
                resetHitboxMode | 8;
        }
    }
    return 0;
}

void fn_8015ED1C(int p1, int p2, int p3);

#pragma scheduling off
#pragma peephole off
static inline u8 scarab_isObjectInList(void* o)
{
    extern int*ObjList_GetObjects(int* startIndex, int* objectCount);
    int i;
    int count;
    int* objs = ObjList_GetObjects(&i, &count);
    while (i < count)
    {
        if (o == (void*)objs[i++])
        {
            return 1;
        }
    }
    return 0;
}

void fn_8015FCCC(int obj);

void iceball_update(undefined2* param_1, int param_2);

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
void FUN_8016043c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

undefined4
FUN_80160798(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10)
{
    float fVar1;
    int iVar2;
    undefined8 uVar3;

    iVar2 = *(int*)&((GameObject*)param_9)->extra;
    if (*(int*)(param_10 + 0x2d0) == 0)
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 0);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 1);
        fVar1 = lbl_803E3B00;
        *(float*)(param_10 + 0x290) = lbl_803E3B00;
        *(float*)(param_10 + 0x28c) = fVar1;
        FUN_80003494(iVar2 + 0x35c, param_9 + 0xc, 0xc);
        uVar3 = FUN_80003494(iVar2 + 0x368, *(int*)(param_10 + 0x2d0) + 0xc, 0xc);
        FUN_80006a54(uVar3, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
        if ((*(float*)(param_10 + 0x2c0) < lbl_803E3B04) && (*(char*)(iVar2 + 0x405) == '\x02'))
        {
            return 5;
        }
        if (*(char*)(iVar2 + 0x381) == '\0')
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(iVar2 + 0x374), (double)*(float*)(iVar2 + 0x37c),
             (double)lbl_803E3B00, (double)lbl_803E3B00, (double)lbl_803E3B08, param_9,
             param_10);
        }
        else
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(iVar2 + 0x374), (double)*(float*)(iVar2 + 0x37c),
             (double)lbl_803E3B0C, (double)lbl_803E3B10, (double)lbl_803E3B08, param_9,
             param_10);
        }
    }
    return 0;
}

undefined4
FUN_80160aa4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    undefined4 uVar2;
    ObjHitsPriorityState* hitState;

    if (*(char*)(param_10 + 0x27b) == '\0')
    {
        iVar1 = FUN_80017a98();
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar1, 0xe0000,
                            param_9, 0, param_13, param_14, param_15, param_16);
        if (*(int*)&((GameObject*)param_9)->anim.placementData == 0)
        {
            FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
            uVar2 = 0;
        }
        else
        {
            uVar2 = 4;
        }
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 3);
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(undefined*)(param_10 + 0x25f) = 0;
        *(undefined*)(param_10 + 0x349) = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
        hitState->flags &= ~1;
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        uVar2 = 0;
    }
    return uVar2;
}

undefined4
FUN_80160cd0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 uVar1;

    uVar1 = *(undefined4*)(param_9 + 0xb8);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B00, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x25f) = 1;
    *(undefined2*)(param_9 + 4) = *(undefined2*)(param_10 + 0x19e);
    *(undefined2*)(param_9 + 2) = *(undefined2*)(param_10 + 0x19c);
    (**(code**)(*DAT_803dd738 + 0x10))
        ((double)lbl_803E3B24, (double)lbl_803E3B28, param_9, param_10, uVar1);
    *(float*)(param_10 + 0x2a0) = lbl_803E3B2C * *(float*)(param_10 + 0x280);
    return 0;
}

void FUN_80161130(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
    undefined4 uVar1;
    undefined8 uVar2;

    uVar1 = *(undefined4*)&((GameObject*)param_9)->extra;
    uVar2 = ObjGroup_RemoveObject(param_9, 3);
    if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
    {
        FUN_80017ac8(uVar2, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     *(int*)&((GameObject*)param_9)->childObjs[0]);
        *(undefined4*)&((GameObject*)param_9)->childObjs[0] = 0;
    }
    (**(code**)(*DAT_803dd738 + 0x40))(param_9, uVar1, 1);
    return;
}

undefined4
FUN_801615d4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             int param_10)
{
    undefined4 uVar1;

    if (*(char*)(param_10 + 0x27b) != '\0')
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 8);
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(undefined*)(param_10 + 0x25f) = 0;
        *(undefined*)(param_10 + 0x349) = 0;
        param_1 = ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
    }
    if (((GameObject*)param_9)->anim.alpha == 0)
    {
        if (*(int*)&((GameObject*)param_9)->anim.placementData == 0)
        {
            FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
            uVar1 = 0;
        }
        else
        {
            uVar1 = 6;
        }
    }
    else
    {
        uVar1 = 0;
    }
    return uVar1;
}

undefined4
FUN_80161c08(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;

    iVar1 = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B80;
    if ((*(uint*)(param_10 + 0x314) & 0x200) != 0)
    {
        FUN_80006824(param_9, SFXdoor_creak);
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & 0xfffffdff;
        (**(code**)(*DAT_803dd738 + 0x4c))(param_9, (int)*(short*)(iVar1 + 0x3f0), 0xffffffff, 1);
    }
    return 0;
}

undefined4
FUN_80161ea0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    uint uVar1;
    int iVar2;
    undefined4 uVar3;
    int iVar4;
    double dVar5;
    ObjHitsPriorityState* hitState;
    float local_48;
    float local_44;
    float local_40;
    float local_3c;
    float local_38;
    float local_34[2];
    uint uStack_2c;

    iVar4 = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    hitState->hitVolumePriority = 9;
    hitState->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    uVar1 = randomGetRange(0, 100);
    if ((int)uVar1 < 0x32)
    {
        if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 1, 0, param_12, param_13, param_14, param_15, param_16);
            *(undefined*)(param_10 + 0x346) = 0;
        }
    }
    else if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 4, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 1);
    uStack_2c = *(char*)(iVar4 + 0x45) * -2 + 1U ^ 0x80000000;
    local_34[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(iVar4 + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)uStack_2c),
        *(int*)(iVar4 + 0x38), iVar4 + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(iVar4 + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(iVar4 + 0x48))
        {
            *(float*)(iVar4 + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(iVar4 + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(iVar4 + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(iVar4 + 0x48) - lbl_803E3B94), *(int*)(iVar4 + 0x38), &local_48,
     &local_44, &local_40);
    (**(code**)(**(int**)(*(int*)(iVar4 + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(iVar4 + 0x48)), *(int*)(iVar4 + 0x38), &local_3c,
     &local_38, local_34);
    local_48 = local_48 - local_3c;
    local_44 = local_44 - local_38;
    local_40 = local_40 - local_34[0];
    dVar5 = FUN_80293900((double)(local_48 * local_48 + local_40 * local_40));
    local_48 = (float)dVar5;
    iVar2 = FUN_80017730();
    ((GameObject*)param_9)->anim.rotY = (short)iVar2 * ((short)((int)*(char*)(iVar4 + 0x45) << 1) + -1);
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        uVar3 = 0;
    }
    else
    {
        uVar3 = 5;
    }
    return uVar3;
}

void dll_CA_release_nop(void);

void chukchuk_free(void)
{
}

void chukchuk_hitDetect(void)
{
}

void chukchuk_release(void)
{
}

void chukchuk_initialise(void)
{
}

/*
 * Per-object extra state for the ChukChuk ice-spitter
 * (chukchuk_getExtraSize == 0x18).
 */

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

#pragma scheduling off
#pragma peephole off
void chukchuk_init(u8* obj, u8* params)
{
    ChukChukState* sub = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
    sub->gameBit = *(s16*)(params + 0x18);
    if (sub->gameBit != -1 && GameBit_Get(sub->gameBit) != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        sub->flags = (u8)(sub->flags | 0x2);
    }
    else
    {
        sub->triggerDistance = (u16)(params[0x29] << 3);
        sub->unk08 = *(s16*)(params + 0x22);
        sub->hitsLeft = params[0x32];
        sub->arcHalfAngle = (u16)((s8)params[0x28] * 0xb6);
        sub->attackChance = params[0x2f];
        sub->aimHeightY = params[0x27];
        *(s16*)obj = (s16)((s8)params[0x2a] << 8);
    }
}
void iceball_hitDetect(void);

void iceball_release(void);

void iceball_initialise(void);

int chukchuk_getExtraSize(void) { return 0x18; }
int chukchuk_getObjectTypeId(void) { return 0x0; }
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E2E30);
}

void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_free(void);

void fn_8015F5B0(short* obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern int Obj_AllocObjectSetup(int size, int id);
    extern u8*Obj_SetupObject(int setup, int a, int b, int c, int d);
    extern int Obj_GetPlayerObject(void);
    extern f64 lbl_803E2E28;
    extern f32 lbl_803E2E20;
    extern f32 lbl_803E2E24;
    ChukChukState* sub;
    int setup;
    u8* o;
    int pl;
    f32 sc;

    sub = ((GameObject*)obj)->extra;
    if (Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(36, 1307);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = lbl_803E2E20 + ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s8*)(setup + 4) = 1;
        *(s8*)(setup + 5) = 4;
        *(u8*)(setup + 7) = 0xff;
        o = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (o != NULL)
        {
            pl = Obj_GetPlayerObject();
            ((GameObject*)o)->anim.velocityX = (*(f32*)(pl + 0xc) - ((GameObject*)obj)->anim.localPosX) / (sc =
                lbl_803E2E24);
            ((GameObject*)o)->anim.velocityY =
                ((*(f32*)(pl + 0x10) + (f32)(u32)
            sub->aimHeightY
            )
            -((GameObject*)obj)->anim.localPosY
            )
            /
            sc;
            ((GameObject*)o)->anim.velocityZ = (*(f32*)(pl + 0x14) - ((GameObject*)obj)->anim.localPosZ) / sc;
        }
    }
}

void chukchuk_update(short* obj)
{
    extern void objParticleFn_80099d84(f32, short*, int, f32, int);
    extern int Obj_GetPlayerObject(void);
    extern int getAngle(f32 deltaX, f32 deltaZ);
    extern f32 sqrtf(f32);
    extern void GameBit_Set(int bit, int val);
    extern void fn_8015F5B0(short* obj);
    extern u8 lbl_8031FF80[];
    extern f32 timeDelta;
    extern f64 lbl_803E2E48;
    extern f32 lbl_803E2E30;
    extern f32 lbl_803E2E34;
    extern f32 lbl_803E2E38;
    extern f32 lbl_803E2E3C;
    extern f32 lbl_803E2E40;
    ChukChukState* v;
    u16 di;
    int pl;
    ObjTextureRuntimeSlot* tex;
    int ang;
    int r;
    f32 ph;
    f32 lim;
    f32 nv;
    f32 dx;
    f32 dz;
    struct
    {
        int c;
        int b;
        int a;
        f32 d[3];
    } stk;

    v = ((GameObject*)obj)->extra;
    if (v->steamTimer != lbl_803E2E34)
    {
        v->steamTimer -= timeDelta;
        objParticleFn_80099d84(lbl_803E2E30, obj, 1, v->steamTimer / lbl_803E2E38, 0);
        if (v->steamTimer <= *(f32*)&lbl_803E2E34)
        {
            v->steamTimer = lbl_803E2E34;
        }
    }
    if ((v->flags & 2) == 0)
    {
        tex = objFindTexture((void*)obj, 0, 0);
        if (v->glowPhase < lbl_803E2E3C)
        {
            if ((int)v->glowPhase == 10)
            {
                v->flags |= 1;
            }
            tex->textureId = lbl_8031FF80[(int)v->glowPhase] << 8;
            lim = lbl_803E2E3C;
            nv = v->glowPhase + lbl_803E2E30;
            v->glowPhase = nv;
            if (lim == nv)
            {
                v->glowPhase = (f32)(int)
                randomGetRange(16, 245);
            }
        }
        else
        {
            if (lbl_803E2E40 - v->glowPhase >= timeDelta)
            {
                v->glowPhase = v->glowPhase + timeDelta;
            }
            else
            {
                v->glowPhase = lbl_803E2E34;
            }
            tex->textureId = 0;
        }
        pl = Obj_GetPlayerObject();
        dx = *(f32*)(pl + 0xc) - ((GameObject*)obj)->anim.localPosX;
        dz = *(f32*)(pl + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        di = sqrtf(dx * dx + dz * dz);
        if (di < v->triggerDistance)
        {
            if (v->prevDistance >= v->triggerDistance)
            {
                v->flags = 5;
                v->glowPhase = lbl_803E2E34;
            }
            if ((v->flags & 5) != 0)
            {
                stk.d[0] = *(f32*)(pl + 0x18) - ((GameObject*)obj)->anim.worldPosX;
                stk.d[1] = *(f32*)(pl + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
                stk.d[2] = *(f32*)(pl + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
                ang = getAngle(stk.d[0], stk.d[2]) & 0xffff;
                ang -= *obj & 0xffff;
                if (ang > 0x8000)
                {
                    ang -= 0xffff;
                }
                if (ang < -0x8000)
                {
                    ang += 0xffff;
                }
                if (((u32)ang & 0xffff) < v->arcHalfAngle ||
                    ((u32)ang & 0xffff) > ((0xffff - v->arcHalfAngle) & 0xffff))
                {
                    r = randomGetRange(0, 99);
                    if (r < v->attackChance || (v->flags & 4) != 0)
                    {
                        Sfx_PlayFromObject(obj, SFXkr_impact1);
                        fn_8015F5B0(obj);
                    }
                    else
                    {
                        Sfx_PlayFromObject(obj, SFXkr_impact2);
                    }
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXkr_impact2);
                }
            }
        }
        else if ((v->flags & 1) != 0)
        {
            Sfx_PlayFromObject(obj, SFXkr_impact2);
        }
        v->prevDistance = di;
        if (ObjHits_GetPriorityHit(obj, &stk.a, &stk.b, &stk.c) == 14)
        {
            v->hitsLeft -= 1;
            if (v->hitsLeft < 1)
            {
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->anim.flags |= 0x4000;
                v->flags |= 2;
                Sfx_PlayFromObject(obj, SFXkr_impact3);
                GameBit_Set(v->gameBit, 1);
                v->steamTimer = lbl_803E2E38;
                Sfx_PlayFromObject(obj, SFXfoot_ice_run_4);
            }
        }
        v->flags &= ~5;
    }
}

#pragma scheduling on
#pragma peephole on
void chukchuk_setScale(int obj, int v)
{
    switch ((u8)v)
    {
    case 0x80:
        Sfx_PlayFromObject(obj, SFXkr_jump1);
        break;
    }
}

void iceball_init(void* obj);

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)chukchuk_initialise,
        (ObjectDescriptorCallback)chukchuk_release,
        0,
        (ObjectDescriptorCallback)chukchuk_init,
        (ObjectDescriptorCallback)chukchuk_update,
        (ObjectDescriptorCallback)chukchuk_hitDetect,
        (ObjectDescriptorCallback)chukchuk_render,
        (ObjectDescriptorCallback)chukchuk_free,
        (ObjectDescriptorCallback)chukchuk_getObjectTypeId,
        chukchuk_getExtraSize,
        (ObjectDescriptorCallback)chukchuk_setScale,
    },
    0,
};

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)iceball_initialise,
    (ObjectDescriptorCallback)iceball_release,
    0,
    (ObjectDescriptorCallback)iceball_init,
    (ObjectDescriptorCallback)iceball_update,
    (ObjectDescriptorCallback)iceball_hitDetect,
    (ObjectDescriptorCallback)iceball_render,
    (ObjectDescriptorCallback)iceball_free,
    (ObjectDescriptorCallback)iceball_getObjectTypeId,
    iceball_getExtraSize,
};

/* scarab_updateProximityGate: scarab AI proximity gate. If no current target, dispatches
 * vtable[5](obj, state, 0) and returns 1. Else (unless state mode 6 means
 * already engaged) reads the angle from the obj to the target; when within
 * a +/-90? wedge the planar distance term is the constant lbl_803E2EB0,
 * otherwise it's sqrtf(dx*dx + dz*dz) - lbl_803E2EB4. The signed magnitude
 * drives three threshold checks against lbl_803E2EBC/EC0/EC4 that issue
 * vtable[5] calls with mode 6 (close), 1 (medium-out), or 1 (close-in)
 * depending on the current mode at (*(u8 *)&state->baddie.controlMode) and the latch byte at
 * state->baddie.moveDone. When mode == 1, picks one of two scalars (lbl_803E2EC8 or
 * lbl_803E2ECC) for (*(u8 *)&state->baddie.moveSpeed). Returns 0. */
