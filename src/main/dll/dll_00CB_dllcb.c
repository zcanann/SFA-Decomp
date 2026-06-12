#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/scarab.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct DllCBPlacement
{
    u8 pad0[0x4 - 0x0];
    s8 unk4;
    s8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[0x24 - 0x14];
    s16 unk24;
    u8 pad26[0x2C - 0x26];
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DllCBPlacement;


typedef struct DllCBState
{
    f32 unk0;
    f32 unk4;
    u8 pad8[0x3DC - 0x8];
    void* unk3DC;
    s32 unk3E0;
    u8 pad3E4[0x3F6 - 0x3E4];
    s16 gameBitId;
    u8 pad3F8[0x3FE - 0x3F8];
    u16 unk3FE;
    u16 unk400;
    u8 pad402[0x405 - 0x402];
    s8 unk405;
    u8 pad406[0x408 - 0x406];
} DllCBState;


typedef struct GrimbleState
{
    u8 pad0[0x38 - 0x0];
    s32 unk38;
    u8 pad3C[0x45 - 0x3C];
    s8 unk45;
    u8 pad46[0x48 - 0x46];
    f32 unk48;
    u8 pad4C[0x58 - 0x4C];
    s16 unk58;
    u8 pad5A[0x60 - 0x5A];
} GrimbleState;


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
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined8 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_8003b818();
extern double FUN_80293900();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern EffectInterface** gPartfxInterface;
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

/*
 * --INFO--
 *
 * Function: dll_CA_update
 * EN v1.0 Address: 0x8015D7B0
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x8015D86C
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: FUN_8015d99c
 * EN v1.0 Address: 0x8015D99C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8015DA64
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off
int fn_8015E3A0(int obj, int p2);

/*
 * --INFO--
 *
 * Function: FUN_8015e0d0
 * EN v1.0 Address: 0x8015E0D0
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x8015E3CC
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
#pragma scheduling on
#pragma peephole on
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

#pragma scheduling off
#pragma peephole off
int fn_8015E210(int* obj, GroundBaddieState* state);

/*
 * --INFO--
 *
 * Function: FUN_8015e260
 * EN v1.0 Address: 0x8015E260
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x8015E4F0
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8015e2e0
 * EN v1.0 Address: 0x8015E2E0
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8015E574
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_8015e488
 * EN v1.0 Address: 0x8015E488
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x8015E6BC
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

#pragma scheduling off
#pragma peephole off
int fn_8015DC04(int obj, GroundBaddieState* p);

#pragma dont_inline on
void fn_8015DAE8(void);
#pragma dont_inline reset

void dll_CA_init(int obj, u8* p, int flags);

int fn_8015E5DC(short* obj, GroundBaddieState* p);

int fn_8015DF20(int obj, GroundBaddieState* p);

int fn_8015E0C8(int obj, GroundBaddieState* p);

int fn_8015E798(int obj, GroundBaddieState* p);

int fn_8015E8BC(int obj, GroundBaddieState* p);

void fn_8015EA48(int obj, GroundBaddieState* state);

/*
 * --INFO--
 *
 * Function: FUN_8015e678
 * EN v1.0 Address: 0x8015E678
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x8015E84C
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
#pragma scheduling on
#pragma peephole on
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

    iVar4 = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    iVar3 = -1;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairPriority = 10;
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairHitVolume = 1;
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

/*
 * --INFO--
 *
 * Function: FUN_8015e88c
 * EN v1.0 Address: 0x8015E88C
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8015E9CC
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e88c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 uVar1;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar1 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairPriority = 10;
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairHitVolume = 1;
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

/*
 * --INFO--
 *
 * Function: FUN_8015e9f4
 * EN v1.0 Address: 0x8015E9F4
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x8015EA88
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

    iVar5 = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    iVar4 = -1;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairPriority = 10;
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairHitVolume = 1;
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

#pragma scheduling off
#pragma peephole off
void fn_8015EB6C(int obj, int p2, int p3);

/*
 * --INFO--
 *
 * Function: FUN_8015ec98
 * EN v1.0 Address: 0x8015EC98
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8015EC44
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
#pragma scheduling on
#pragma peephole on
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

#pragma scheduling off
#pragma peephole off
void fn_8015ED1C(int p1, int p2, int p3);

/*
 * --INFO--
 *
 * Function: dll_CE_func0B
 * EN v1.0 Address: 0x8015EE98
 * EN v1.0 Size: 464b
 * EN v1.1 Address: 0x8015ED68
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_CE_func0B(int obj, int v);

void dll_CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dll_CE_init(int obj, u8* p, int flags);

void dll_CE_update(int obj, int p2, int p3);

/*
 * --INFO--
 *
 * Function: FUN_8015f068
 * EN v1.0 Address: 0x8015F068
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x8015EEF4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_8015FBEC(int obj);
#pragma dont_inline reset

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

/*
 * --INFO--
 *
 * Function: FUN_8015fb0c
 * EN v1.0 Address: 0x8015FB0C
 * EN v1.0 Size: 1212b
 * EN v1.1 Address: 0x8015FBEC
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int getTrickyObject(void);
extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;
extern f32 lbl_803E2E54;
extern f32 lbl_803E2E58;

/*
 * --INFO--
 *
 * Function: iceball_update
 * EN v1.0 Address: 0x8015FFC8
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x8015FF9C
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void iceball_update(undefined2* param_1, int param_2);

int fn_801601C4(int obj, GroundBaddieState* p)
{
    extern int* gPlayerInterface;
    extern void*memcpy(void* dst, const void* src, int n);
    extern void voxmaps_updateRoutePath(char* a, char* b);
    extern f32 lbl_803E2E68;
    extern f32 lbl_803E2E6C;
    extern f32 lbl_803E2E70;
    extern f32 lbl_803E2E74;
    extern f32 lbl_803E2E78;
    GroundBaddieState* sub;
    char* wp;
    f32 z;

    sub = ((GameObject*)obj)->extra;
    if (*(void**)&p->baddie.targetObj != NULL)
    {
        (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 1);
        wp = (char*)sub->route35C;
        z = lbl_803E2E68;
        p->baddie.moveInputX = z;
        p->baddie.moveInputZ = z;
        memcpy(wp, (void*)&((GameObject*)obj)->anim.localPosX, 12);
        memcpy((void*)(sub->route35C + 0xc), (void*)(*(int*)&p->baddie.targetObj + 0xc), 12);
        voxmaps_updateRoutePath(wp, (char*)(sub->route35C + 0x28));
        if (p->baddie.targetDistance < lbl_803E2E6C && sub->unk405 == 2)
        {
            return 5;
        }
        if (*(u8*)(wp + 0x25) == 0)
        {
            (*(void (**)(int, u8*, f32, f32, f32, f32, f32))(*(int*)gPlayerInterface + 0x1c))(
                obj, (u8*)p, *(f32*)(wp + 0x18), *(f32*)(wp + 0x20), lbl_803E2E68, *(f32*)&lbl_803E2E68,
                lbl_803E2E70);
        }
        else
        {
            (*(void (**)(int, u8*, f32, f32, f32, f32, f32))(*(int*)gPlayerInterface + 0x1c))(
                obj, (u8*)p, *(f32*)(wp + 0x18), *(f32*)(wp + 0x20), lbl_803E2E74, lbl_803E2E78,
                lbl_803E2E70);
        }
    }
    else
    {
        (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    return 0;
}

int fn_8016043C(int obj, GroundBaddieState* p)
{
    extern int* gPlayerInterface;
    extern int Obj_GetPlayerObject(void);
    extern void ObjMsg_SendToObject(int target, int msg, int from, int a);
    extern void Obj_FreeObject(int* obj);

    if (*(char*)&p->baddie.moveJustStartedB != '\0')
    {
        (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 3);
        *(int*)&p->baddie.targetObj = 0;
        *(s8*)&p->baddie.physicsActive = 0;
        *(s8*)&p->baddie.hasTarget = 0;
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    else
    {
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0xe0000, obj, 0);
        if (((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject((int*)obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

#pragma dont_inline on
void fn_801606F0(int obj, void* p2, int sub, GroundBaddieState* p)
{
    extern int* gBaddieControlInterface;
    extern ObjectTriggerInterface** gObjectTriggerInterface;
    extern int* gPlayerInterface;
    extern void* lbl_803AC5D0[];
    extern void* lbl_803AC5E8[];
    extern f32 timeDelta;
    extern f64 lbl_803E2EA0;
    extern f32 lbl_803E2E9C;
    int setup;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    *(s8*)&p->baddie.moveDone = 1;
    if ((*(int (**)(int, u8*, f32, int))(*(int*)gBaddieControlInterface + 0x44))(
        obj, (u8*)p, (f32)(u32) * (u16*)(sub + 0x3fe), 1) != 0)
    {
        *(int*)&p->baddie.targetObj = *(int*)(sub + 0x3e0);
        *(s8*)&p->baddie.hasTarget = 0;
        if (*(char*)(setup + 0x2e) != -1)
        {
            if (p2 != NULL)
            {
                (*gObjectTriggerInterface)->yield((ObjSeqState*)p2, *(s16*)(setup + 0x24));
            }
            *(s8*)(sub + 0x405) = 1;
        }
        else
        {
            *(int*)&p->baddie.targetObj = 0;
        }
    }
    (*(void (**)(int, u8*, f32, int))(*(int*)gBaddieControlInterface + 0x2c))(obj, (u8*)p,
                                                                              lbl_803E2E9C, 1);
    *(int*)(sub + 0x3e0) = *(int*)&((GameObject*)obj)->pendingParentObj;
    *(int*)&((GameObject*)obj)->pendingParentObj = 0;
    (*(void (**)(int, u8*, f32, f32, void*, void*))(*(int*)gPlayerInterface + 8))(
        obj, (u8*)p, timeDelta, timeDelta, lbl_803AC5E8, lbl_803AC5D0);
    *(int*)&((GameObject*)obj)->pendingParentObj = *(int*)(sub + 0x3e0);
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_8016083C(int* obj, GroundBaddieState* sub, GroundBaddieState* p)
{
    extern void characterDoEyeAnims(int* obj, u8* a);
    extern f32 sqrtf(f32);
    extern int Obj_GetPlayerObject(void);
    extern int* gBaddieControlInterface;
    extern u8 lbl_80320008[];
    extern u8 lbl_80320080[];
    char* o;
    int t;
    struct
    {
        f32 x, y, z;
    } d;
    f32* dp = &d.x;

    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        *(int*)(*(int*)&((GameObject*)obj)->childObjs[0] + 0x30) = *(int*)&((GameObject*)obj)->anim.parent;
    }
    o = *(char**)&p->baddie.targetObj;
    if (o != NULL)
    {
        d.x = ((GameObject*)o)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d.y = ((GameObject*)o)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d.z = ((GameObject*)o)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        p->baddie.targetDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }
    characterDoEyeAnims(obj, sub->route35C + 0x50);
    if ((sub->configFlags & 1) == 0)
    {
        (*(void (**)(int*, u8*, u8*, int, int, int, int))(*(int*)gBaddieControlInterface + 0x3c))(
            obj, (u8*)p, (u8*)&sub->flags400, 2, 3, sub->unk3FC, sub->unk3FA);
    }
    (*(void (**)(int*, u8*, u8*, int, u8*, int, int, int))(*(int*)gBaddieControlInterface +
        0x54))(
        obj, (u8*)p, sub->route35C, sub->gameBitB, &sub->unk405, 0, 0, 0);
    t = (*(int (**)(int*, u8*, u8*, int, u8*, u8*, int, int))(*(int*)gBaddieControlInterface +
        0x50))(
        obj, (u8*)p, sub->route35C, sub->gameBitB, lbl_80320008, lbl_80320080, 1, 0);
    if (t >= 4)
    {
        *(s8*)&sub->unk405 = 2;
        *(int*)&p->baddie.targetObj = Obj_GetPlayerObject();
    }
}
#pragma dont_inline reset

int dll_CB_seqFn(short* obj, int p2, u8* e)
{
    extern u32 GameBit_Get(int bit);
    extern int Curve_AdvanceAlongPath(int* p, f32 t);
    extern int getAngle(f32 a, f32 b);
    extern int* gBaddieControlInterface;
    extern ObjectTriggerInterface** gObjectTriggerInterface;
    extern int* gPlayerInterface;
    extern void* lbl_803AC5D0[];
    extern void* lbl_803AC5E8[];
    extern f32 lbl_803E2E8C;
    extern f32 lbl_803E2E98;
    extern f32 lbl_803E2E9C;
    int setup;
    int* path;
    int sub;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    sub = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        return 0;
    }
    if (((GameObject*)obj)->seqIndex != -1)
    {
        if ((*(int (**)(short*, int, int))(*(int*)gBaddieControlInterface + 0x30))(obj, sub, 1) ==
            0)
        {
            return 1;
        }
        fn_8016083C((int*)obj, (GroundBaddieState*)sub, (GroundBaddieState*)sub);
        if (((DllCBState*)sub)->gameBitId != -1 && GameBit_Get(((DllCBState*)sub)->gameBitId) != 0)
        {
            (*gObjectTriggerInterface)->yield((ObjSeqState*)e, ((DllCBPlacement*)setup)->unk2C);
            ((DllCBState*)sub)->gameBitId = -1;
        }
        switch (*(u8*)&((DllCBState*)sub)->unk405)
        {
        case 2:
            *(s16*)(e + 0x6e) = 0;
            fn_801606F0((int)obj, e, sub, (GroundBaddieState*)sub);
            if (*(u8*)&((DllCBState*)sub)->unk405 == 1)
            {
                ((GroundBaddieState*)sub)->baddie.substate = 5;
                (*(void (**)(short*, int, f32, f32, void*, void*))(*(int*)gPlayerInterface + 8))(
                    obj, sub, lbl_803E2E8C, *(f32*)&lbl_803E2E8C, lbl_803AC5E8, lbl_803AC5D0);
                *(s8*)(e + 0x56) = 0;
            }
            break;
        case 1:
            if ((*(int (**)(short*, u8*, int, void*, void*, int))(*(int*)gBaddieControlInterface +
                0x34))(
                obj, e, sub, lbl_803AC5E8, lbl_803AC5D0, 0) != 0)
            {
                (*(void (**)(short*, int, f32, int))(*(int*)gBaddieControlInterface + 0x2c))(obj, sub, lbl_803E2E9C, 1);
            }
            break;
        case 0:
        default:
            *(s16*)(e + 0x6e) = -1;
            *(s16*)(e + 0x6e) &= ~0x40;
            path = *(int**)&((DllCBState*)sub)->unk3DC;
            if ((((DllCBState*)sub)->unk400 & 8) != 0)
            {
                if ((Curve_AdvanceAlongPath(path, ((GroundBaddieState*)sub)->baddie.animSpeedA) != 0 || path[4] != 0) &&
                    (*gRomCurveInterface)->goNextPoint(path) != 0)
                {
                    ((DllCBState*)sub)->unk400 &= ~8;
                }
                ((GroundBaddieState*)sub)->baddie.animSpeedA = lbl_803E2E98;
                ((GameObject*)obj)->anim.rotX = getAngle(*(f32*)((char*)path + 0x74), *(f32*)((char*)path + 0x7c)) +
                    0x8000;
                ((GameObject*)obj)->anim.rotY = getAngle(*(f32*)((char*)path + 0x7c), *(f32*)((char*)path + 0x78)) +
                    0x4000;
                ((GameObject*)obj)->anim.rotZ = getAngle(*(f32*)((char*)path + 0x78), *(f32*)((char*)path + 0x74)) +
                    0x4000;
                ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)path + 0x68);
                ((GameObject*)obj)->anim.localPosY = *(f32*)((char*)path + 0x6c);
                ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)path + 0x70);
            }
            break;
        }
    }
    if (((GameObject*)obj)->seqIndex == -1)
    {
        ((DllCBState*)sub)->unk400 |= 2;
        return 0;
    }
    return *(u8*)&((DllCBState*)sub)->unk405 != 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801600a8
 * EN v1.0 Address: 0x801600A8
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x80160098
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8016043c
 * EN v1.0 Address: 0x8016043C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80160440
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016043c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_80160798
 * EN v1.0 Address: 0x80160798
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x80160670
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_80160aa4
 * EN v1.0 Address: 0x80160AA4
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x801608E8
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80160aa4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    undefined4 uVar2;

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
        (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->flags &= ~1;
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        uVar2 = 0;
    }
    return uVar2;
}


/*
 * --INFO--
 *
 * Function: FUN_80160cd0
 * EN v1.0 Address: 0x80160CD0
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80160A80
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_80161130
 * EN v1.0 Address: 0x80161130
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80161180
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_801615d4
 * EN v1.0 Address: 0x801615D4
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x80161638
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_80161c08
 * EN v1.0 Address: 0x80161C08
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80161B58
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_80161ea0
 * EN v1.0 Address: 0x80161EA0
 * EN v1.0 Size: 888b
 * EN v1.1 Address: 0x80161D2C
 * EN v1.1 Size: 632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    float local_48;
    float local_44;
    float local_40;
    float local_3c;
    float local_38;
    float local_34[2];
    uint uStack_2c;

    iVar4 = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    ((ObjHitsPriorityState*)*(int*)&((GameObject*)param_9)->anim.hitReactState)->hitVolumePriority = 9;
    ((ObjHitsPriorityState*)*(int*)&((GameObject*)param_9)->anim.hitReactState)->hitVolumeId = 1;
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


/* Trivial 4b 0-arg blr leaves. */
void dll_CA_release_nop(void);

void dll_CE_hitDetect_nop(void);

void dll_CE_release_nop(void);

void chukchuk_free(void);

void chukchuk_hitDetect(void);

void chukchuk_release(void);

void chukchuk_initialise(void);

extern uint GameBit_Get(int eventId);

/*
 * Per-object extra state for the ChukChuk ice-spitter
 * (chukchuk_getExtraSize == 0x18).
 */
typedef struct ChukChukState
{
    f32 glowPhase; /* texture glow ramp index; 10 primes an attack, resets to rand(16,245) */
    f32 steamTimer; /* counts down after destruction, scales the steam particle */
    s16 unk08; /* from params+0x22 */
    s16 gameBit; /* set on destruction; already-set disables on load */
    u16 triggerDistance; /* params[0x29] << 3 */
    u16 arcHalfAngle; /* (s8)params[0x28] * 182 -- facing wedge for the spit attack */
    u16 prevDistance; /* player planar distance last frame */
    u8 flags; /* 1 primed, 2 dead/disabled, 4 forced attack */
    u8 hitsLeft;
    u8 attackChance; /* percent, vs rand(0,99) */
    u8 aimHeightY; /* added to player Y when aiming the iceball */
    u8 pad16[2];
} ChukChukState;

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

#pragma scheduling off
#pragma peephole off
void chukchuk_init(u8* obj, u8* params);
#pragma scheduling on
#pragma peephole on
void iceball_hitDetect(void);

void iceball_release(void);

void iceball_initialise(void);

void dll_CB_func0B_nop(void)
{
}

void dll_CB_release_nop(void)
{
}

extern f32 lbl_803E2EA8;

#pragma scheduling off
#pragma peephole off
void dll_CB_init(int* obj, u8* params, int extra)
{
    extern int* gBaddieControlInterface;
    extern int* gPlayerInterface;
    GroundBaddieState* sub;
    u8 flags;

    sub = ((GameObject*)obj)->extra;
    flags = 0x16;
    if (extra != 0) flags |= 1;
    if ((params[0x2b] & 1) == 0) flags |= 8;
    ((GameObject*)obj)->anim.rotY = (s16)((s8)params[0x28] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s8)params[0x27] << 8);
    ((void(*)(int*, u8*, u8*, int, int, int, u8, f32))((void**)*(int*)gBaddieControlInterface)[22])(
        obj, params, (u8*)sub, 4, 6, 0x82, flags, lbl_803E2EA8);
    ((GameObject*)obj)->animEventCallback = (void*)dll_CB_seqFn;
    ((void(*)(int*, u8*, int))((void**)*(int*)gPlayerInterface)[5])(obj, (u8*)sub, 0);
    sub->baddie.substate = 0;
    if (sub->aggroRange < 0x32)
    {
        sub->aggroRange = 0x32;
    }
}


extern int Curve_AdvanceAlongPath(int* p, f32 t);
extern int getAngle(f32 a, f32 b);
extern f32 lbl_803E2E98;

void dll_CB_update(int* obj)
{
    extern int* gBaddieControlInterface;
    int* path;
    GroundBaddieState* sub;
    u8* def;

    sub = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->unkF4 != 0) return;
    if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((DllCBPlacement*)def)->posX;
        ((GameObject*)obj)->anim.localPosY = ((DllCBPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((DllCBPlacement*)def)->posZ;
        ((GameObject*)obj)->unkF8 = 1;
        return;
    }
    if ((sub->flags400 & 2) != 0)
    {
        ((void(*)(int*, u8*, u8*, s16, u8*, int, int, int, int))((int**)*(int**)gBaddieControlInterface)[10])(
            obj, (u8*)sub, sub->route35C, sub->gameBitB, &sub->unk405, 0, 0, 0, 1);
        sub->flags400 = (u16)(sub->flags400 & ~2);
    }
    if (((int(*)(int*, u8*, int))((int**)*(int**)gBaddieControlInterface)[12])(obj, (u8*)sub, 1) == 0) return;
    fn_8016083C(obj, sub, sub);
    path = *(int**)&sub->path;
    if ((sub->flags400 & 8) == 0) return;
    if (Curve_AdvanceAlongPath(path, sub->baddie.animSpeedA) != 0 || path[4] != 0)
    {
        if ((*gRomCurveInterface)->goNextPoint(path) != 0)
        {
            sub->flags400 = (u16)(sub->flags400 & ~8);
        }
    }
    sub->baddie.animSpeedA = lbl_803E2E98;
    *(s16*)obj = (s16)(getAngle(*(f32*)((char*)path + 0x74), *(f32*)((char*)path + 0x7c)) + 0x8000);
    ((GameObject*)obj)->anim.rotY = (s16)(getAngle(*(f32*)((char*)path + 0x7c), *(f32*)((char*)path + 0x78)) + 0x4000);
    ((GameObject*)obj)->anim.rotZ = (s16)(getAngle(*(f32*)((char*)path + 0x78), *(f32*)((char*)path + 0x74)) + 0x4000);
    ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)path + 0x68);
    ((GameObject*)obj)->anim.localPosY = *(f32*)((char*)path + 0x6c);
    ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)path + 0x70);
}

/* 8b "li r3, N; blr" returners. */
int dll_CE_getExtraSize_ret_1052(void);
int dll_CE_getObjectTypeId(void);
int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);
int fn_8016052C(void) { return 0x6; }
int dll_CB_getExtraSize_ret_1040(void) { return 0x410; }
int dll_CB_getObjectTypeId(void) { return 0x14b; }

/* Pattern wrappers. */
s16 dll_CE_setScale(int* obj);
s16 dll_CB_setScale(int* obj) { return *(s16*)((char*)((int**)obj)[0xb8 / 4] + 0x274); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E2E30;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E2E50;

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* plain forwarder. */
extern void Camera_DisableViewYOffset(void);
void iceball_free(void);


void fn_8015F5B0(short* obj);

void chukchuk_update(short* obj);

/* chukchuk_setScale (52B). If low-byte of arg2 (u8) == 0x80, call Sfx_PlayFromObject(obj, SFXkr_jump1). */
#pragma scheduling on
#pragma peephole on
void chukchuk_setScale(int obj, int v);

/* iceball_init (60B). Sets ->f4 = 0xb4, calls ObjHits_DisableObject(obj), then stb 0xff at 0x36. */
#pragma scheduling off
#pragma peephole off
void iceball_init(void* obj);

/* fn_8016050C (32B). Returns 3 if (s8)obj[0x354] < 1 else 6. */
#pragma scheduling on
int fn_8016050C(int p1, u8* obj)
{
    if ((s8)obj[0x354] < 1) return 3;
    return 6;
}

/* grimble_stateHandlerB03 (32B). Returns 5 if (s8)obj[0x354] < 1 else 1. */
int grimble_stateHandlerB03(int p1, u8* obj);

/* fn_8015E00C (56B). Two-tier select: <1 -> 3, else if obj[0x346]!=0 -> 6 else 0. */
int fn_8015E00C(int p1, u8* obj);

/* grimble_stateHandlerB05 (92B). If obj2->27b != 0, clear obj->b8->405, call GameBit_Set twice. */
extern void GameBit_Set(int eventId, int value);
#pragma scheduling off
int grimble_stateHandlerB05(int* obj, u8* obj2);

/* fn_801603E8 (84B). If obj2->27b != 0, vtable call through gBaddieControlInterface with (obj, x->unk3F0, -1, 0). */
extern undefined4* gBaddieControlInterface;

int fn_801603E8(int* obj, u8* obj2)
{
    GroundBaddieState* x = ((GameObject*)obj)->extra;
    if ((s8)obj2[0x27b] != 0)
    {
        (*(code*)((char*)(*gBaddieControlInterface) + 0x4c))(obj, x->unk3F0, -1, 0);
    }
    return 0;
}

/* dll_CB_hitDetect (60B). Vtable dispatch through gPlayerInterface with extra args (obj->b8, lbl_803AC5E8). */
extern u8 lbl_803AC5E8[];
extern undefined4* gPlayerInterface;
#pragma peephole on
void dll_CB_hitDetect(int* obj)
{
    void* a = ((GameObject*)obj)->extra;
    (*(code*)((char*)(*gPlayerInterface) + 0xc))(obj, a, lbl_803AC5E8);
}

/* dll_CB_render (64B). Render variant: if visible && !obj->f4 then objRenderFn(lbl_803E2E8C). */
extern f32 lbl_803E2E8C;
#pragma scheduling on
#pragma peephole off
void dll_CB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            objRenderFn_8003b8f4(lbl_803E2E8C);
            break;
        }
    }
}

/* fn_801605A8 (44B). Writes float+state fields into obj and copies two halfwords to out. */
extern f32 lbl_803E2E68;
#pragma scheduling off
#pragma peephole on
int fn_801605A8(short* out, u8* obj)
{
    f32 f = lbl_803E2E68;
    *(f32*)(obj + 0x280) = f;
    *(f32*)(obj + 0x284) = f;
    *(s8*)(obj + 0x25f) = 1;
    out[2] = *(s16*)(obj + 0x19e);
    out[1] = *(s16*)(obj + 0x19c);
    return 0;
}

/* fn_80160690 (96B). Like fn_801605A8 but with extra stfs at 0x2a0 and a vtable call. */
int fn_80160690(short* out, u8* obj)
{
    f32 f = lbl_803E2E68;
    *(f32*)(obj + 0x280) = f;
    *(f32*)(obj + 0x284) = f;
    *(f32*)(obj + 0x2a0) = f;
    *(s8*)(obj + 0x25f) = 1;
    out[2] = *(s16*)(obj + 0x19e);
    out[1] = *(s16*)(obj + 0x19c);
    (*(code*)((char*)(*gPlayerInterface) + 0x30))(out, obj, 5);
    return 0;
}

extern f32 lbl_803E2DC8;
extern u8 framesThisStep;

/* Drift-recovery: add new fns with v1.0 names to capture asm symbols. */

#pragma peephole off
int fn_8015DE50(int* obj, GroundBaddieState* state);

int fn_8015DEB4(int* obj, GroundBaddieState* state);

int fn_8015E044(int* obj, GroundBaddieState* state);

extern f32 lbl_803E2DD8;
extern f32 lbl_803E2E7C;
extern f64 lbl_803E2E80;
extern f32 lbl_803E2E88;
extern f32 lbl_803E2EB8;
extern f32 lbl_803E2EE8;

int grimble_stateHandlerA08(int* obj, GroundBaddieState* state);

int fn_8016032C(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        f32 fz;
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 0);
        fz = lbl_803E2E7C;
        ((GameObject*)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.animSpeedC = fz;
    }
    if (((GameObject*)obj)->anim.velocityY < lbl_803E2E80)
    {
        f32 fz = lbl_803E2E68;
        ((GameObject*)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.animSpeedC = fz;
        return 6;
    }
    {
        f32 d = lbl_803E2E88;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY / d;
        state->baddie.animSpeedA = state->baddie.animSpeedA / d;
        state->baddie.animSpeedC = state->baddie.animSpeedC / d;
    }
    return 0;
}

int fn_8015E520(int* obj, GroundBaddieState* state);

int grimble_stateHandlerB04(int* obj, GroundBaddieState* state);

extern void* lbl_803AC5D0[];
extern int fn_801605D4(int* obj, GroundBaddieState* def);
int fn_80160534(int* obj);

extern void* lbl_803AC5B0[];
extern void* lbl_803AC598[];

void dll_CE_initialise(void);

extern f32 lbl_803E2E90;
extern f32 lbl_803E2E94;

int fn_801605D4(int* obj, GroundBaddieState* def)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    if ((s8)def->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2E68, 0);
        *(s8*)&def->baddie.moveDone = 0;
    }
    *(s8*)&def->baddie.physicsActive = 1;
    ((GameObject*)obj)->anim.rotZ = def->baddie.spawnRotZ;
    ((GameObject*)obj)->anim.rotY = def->baddie.spawnRotY;
    ((void(*)(int*, u8*, int*, f32, f32))((void**)*gBaddieControlInterface)[4])(
        obj, (u8*)def, (int*)state, lbl_803E2E8C, lbl_803E2E90);
    def->baddie.moveSpeed = lbl_803E2E94 * def->baddie.animSpeedA;
    return 0;
}

void dll_CB_initialise(void)
{
    ((void**)lbl_803AC5E8)[0] = (void*)fn_80160690;
    ((void**)lbl_803AC5E8)[1] = (void*)fn_801605D4;
    ((void**)lbl_803AC5E8)[2] = (void*)fn_801605A8;
    ((void**)lbl_803AC5E8)[3] = (void*)fn_80160534;
    lbl_803AC5D0[0] = (void*)fn_8016052C;
    lbl_803AC5D0[1] = (void*)fn_8016050C;
    lbl_803AC5D0[2] = (void*)fn_8016043C;
    lbl_803AC5D0[3] = (void*)fn_801603E8;
    lbl_803AC5D0[4] = (void*)fn_8016032C;
    lbl_803AC5D0[5] = (void*)fn_801601C4;
}

#pragma peephole on
int fn_80160534(int* obj)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    u8 step;
    if (((GameObject*)obj)->anim.alpha >= (step = framesThisStep))
    {
        ((GameObject*)obj)->anim.alpha = ((GameObject*)obj)->anim.alpha - step;
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = 0;
    }
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        GameBit_Set(sub->gameBitB, 0);
        GameBit_Set(sub->gameBitA, 1);
    }
    return 0;
}

#pragma peephole off
int grimble_stateHandlerB01(int* obj, GroundBaddieState* state);

int grimble_stateHandlerB00(int obj, GroundBaddieState* p);

int grimble_stateHandlerA09(int obj, GroundBaddieState* p);

int grimble_stateHandlerA06(short* obj, GroundBaddieState* p, f32 spd);

int grimble_stateHandlerA07(short* obj, GroundBaddieState* p);

int grimble_stateHandlerA05(short* obj, GroundBaddieState* p);

int grimble_stateHandlerA04(short* obj, GroundBaddieState* p);

int grimble_stateHandlerA03(short* obj, GroundBaddieState* p);

void dll_CB_free(int* obj)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    {
        int* sub = ((GameObject*)obj)->childObjs[0];
        if (sub != NULL)
        {
            Obj_FreeObject(sub);
            ((GameObject*)obj)->childObjs[0] = NULL;
        }
    }
    ((void(*)(int*, int*, int))((void**)*gBaddieControlInterface)[16])(obj, (int*)state, 1);
}

void dll_CE_free(int* obj);


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

extern f32 sqrtf(f32);
extern f32 lbl_803E2EB0;
extern f32 lbl_803E2EB4;
extern f32 lbl_803E2EBC;
extern f32 lbl_803E2EC0;
extern f32 lbl_803E2EC4;
extern f32 lbl_803E2EC8;
extern f32 lbl_803E2ECC;

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
int scarab_updateProximityGate(int* obj, GroundBaddieState* state);
