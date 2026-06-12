/*
 * sandwormBoss.c - still a 10-DLL container (0x14A CFPowerBase .. 0x157
 * SpiritDoorSpirit) covering [8019D578-801A0B14); see
 * docs/boundary_audit.md. The 0x148/0x149 head was carved to
 * DR/dll_0148_cfguardian.c + DR/dll_0149_cfwindlift.c (skeleton-copy:
 * their defs here are collapsed to prototypes).
 */
#include "main/dll/cfguardian_state.h"
#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "global.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"
#include "main/objseq.h"

extern undefined4 getLActions();
extern undefined8 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined8 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern bool ObjTrigger_UpdateIdBlockFlag(int obj);
extern undefined4 ObjLink_DetachChild();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int Obj_GetYawDeltaToObject();
extern undefined4 objAnimFn_80038f38();
extern void objRenderFn_8003b8f4(f32);
extern undefined4 FUN_8006f7a0();
extern int FUN_8007f924();
extern undefined4 FUN_800e8630();
extern int FUN_801149b8();
extern undefined4 dll_2E_func03();
extern int FUN_8020a468();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80294d40();

extern undefined4 DAT_802c2a58;
extern undefined4 DAT_802c2a5c;
extern undefined4 DAT_802c2a60;
extern undefined4 DAT_802c2a64;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern EffectInterface** gPartfxInterface;
extern f64 DOUBLE_803e4db0;
extern f32 lbl_803DC074;
extern f32 gBoneParticleEffectInterface;
extern f32 gCarryableInterface;
extern f32 lbl_803E4228;
extern f32 lbl_803E4DA8;
extern f32 lbl_803E4DBC;
extern f32 lbl_803E4DC0;
extern f32 lbl_803E4EB0;
extern f32 lbl_803E4EC4;
extern f32 lbl_803E4EC8;
extern f32 lbl_803E4ECC;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4F5C;
extern f32 lbl_803E4F60;
extern f32 lbl_803E4F64;
extern f32 lbl_803E4F68;
extern f32 lbl_803E4F6C;
extern f32 lbl_803E4F70;
extern f32 lbl_803E4F74;

/*
 * --INFO--
 *
 * Function: FUN_8019b1d8
 * EN v1.0 Address: 0x8019B1D8
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x8019B3B8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b1d8(undefined4 param_1, undefined4 param_2, ushort* param_3)
{
    uint uVar1;
    int iVar2;
    int iVar3;
    undefined8 uVar4;

    uVar4 = FUN_80286840();
    uVar1 = (uint)((ulonglong)uVar4 >> 0x20);
    iVar2 = 0;
    for (iVar3 = 0; iVar3 < *(char*)((int)uVar4 + 0x1b); iVar3 = iVar3 + 1)
    {
        switch (*(u8*)((int)uVar4 + iVar3 + 0x13))
        {
        case 0:
            if (param_3 != (ushort*)0x0)
            {
                FUN_80006824(uVar1, *param_3);
            }
            break;
        case 1:
            iVar2 = 1;
            break;
        case 2:
            iVar2 = 2;
            break;
        case 3:
            iVar2 = 3;
            break;
        case 4:
            iVar2 = 4;
            break;
        case 7:
            if (param_3 != (ushort*)0x0)
            {
                FUN_80006824(uVar1, param_3[1]);
            }
            break;
        case 9:
            FUN_80006824(uVar1, SFXsk_trwhin3);
        }
    }
    if ((iVar2 != 0) && (param_3 != (ushort*)0x0))
    {
        FUN_80006824(uVar1, param_3[2]);
    }
    FUN_8028688c();
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_8019b2e0
 * EN v1.0 Address: 0x8019B2E0
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x8019B754
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b2e0(double param_1, short* param_2, short* param_3, float* param_4, undefined4 param_5,
             undefined4 param_6, undefined4 param_7, undefined4 param_8, undefined4 param_9)
{
    int iVar1;
    short sVar2;
    undefined4 uVar3;
    double dVar4;
    double dVar5;
    double dVar6;
    undefined8 in_f5;
    undefined8 in_f6;
    undefined8 in_f7;
    undefined8 in_f8;
    float local_58;
    float local_54;
    float local_50[2];
    undefined4 local_48;
    uint uStack_44;
    undefined4 local_40;
    uint uStack_3c;
    longlong local_38;

    if (param_3 == (short*)0x0)
    {
        uVar3 = 0;
    }
    else
    {
        local_50[0] = *(float*)(param_3 + 6) - *(float*)(param_2 + 6);
        dVar6 = (double)local_50[0];
        local_54 = *(float*)(param_3 + 8) - *(float*)(param_2 + 8);
        local_58 = *(float*)(param_3 + 10) - *(float*)(param_2 + 10);
        dVar4 = FUN_80293900((double)(local_58 * local_58 + (float)(dVar6 * dVar6) + local_54 * local_54
        ));
        if ((double)(float)((double)lbl_803E4DBC * param_1) <= dVar4)
        {
            FUN_8006f7a0(local_50, &local_54, &local_58);
            *(float*)(param_2 + 0x12) = lbl_803DC074 * (float)((double)local_50[0] * param_1);
            *(float*)(param_2 + 0x14) = lbl_803DC074 * (float)((double)local_54 * param_1);
            *(float*)(param_2 + 0x16) = lbl_803DC074 * (float)((double)local_58 * param_1);
            sVar2 = (*param_3 + -0x8000) - *param_2;
            if (0x8000 < sVar2)
            {
                sVar2 = sVar2 + 1;
            }
            if (sVar2 < -0x8000)
            {
                sVar2 = sVar2 + -1;
            }
            uStack_44 = (int)*param_2 ^ 0x80000000;
            local_48 = 0x43300000;
            uStack_3c = (int)sVar2 ^ 0x80000000;
            local_40 = 0x43300000;
            iVar1 = (int)
            ((f32)(s32)
            uStack_44 +
                (float)((double)((lbl_803E4DC0 +
                    (float)((double)CONCAT44(0x43300000, uStack_3c) - DOUBLE_803e4db0
                    )) * (float)(param_1 * (double)lbl_803DC074)) / dVar4)
            )
            ;
            local_38 = (longlong)iVar1;
            *param_2 = (short)iVar1;
            dVar4 = (double)*(float*)(param_2 + 0x14);
            dVar5 = (double)*(float*)(param_2 + 0x16);
            FUN_80017a88((double)*(float*)(param_2 + 0x12), dVar4, dVar5, (int)param_2);
            if (param_2[0x50] != 0x1a)
            {
                FUN_800305f8((double)lbl_803E4DA8, dVar4, dVar5, dVar6, in_f5, in_f6, in_f7, in_f8, param_2, 0x1a, 0
                             , param_5, param_6, param_7, param_8, param_9);
            }
            FUN_8002f6ac(param_1, (int)param_2, param_4);
            uVar3 = 0;
        }
        else
        {
            uVar3 = 1;
        }
    }
    return uVar3;
}


/*
 * --INFO--
 *
 * Function: FUN_8019b650
 * EN v1.0 Address: 0x8019B650
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8019BA44
 * EN v1.1 Size: 3800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b650(undefined8 param_1, double param_2, double param_3, double param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* param_9,
             undefined4 param_10, undefined4 param_11, float* param_12, int param_13, undefined4 param_14
             , undefined4 param_15, undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b658
 * EN v1.0 Address: 0x8019B658
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8019C91C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b658(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , int param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 uVar1;
    int iVar2;
    float* pfVar3;
    undefined4* puVar4;
    undefined4 local_28;
    undefined4 local_24;
    undefined4 local_20;
    undefined4 local_1c;

    pfVar3 = ((GameObject*)param_9)->extra;
    local_28 = DAT_802c2a58;
    local_24 = DAT_802c2a5c;
    local_20 = DAT_802c2a60;
    local_1c = DAT_802c2a64;
    if (((GameObject*)param_9)->seqIndex < 0)
    {
        FUN_800e8630(param_9);
        uVar1 = 0;
    }
    else
    {
        if (*(char*)(pfVar3 + 0x2a0) == '\x06')
        {
            puVar4 = &local_20;
        }
        else
        {
            puVar4 = &local_28;
        }
        iVar2 = FUN_8007f924(param_11);
        if ((iVar2 == 0x283) ||
            (iVar2 = FUN_801149b8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                  , param_11, pfVar3, (short)*puVar4, (short)puVar4[1], param_14, param_15,
                                  param_16), iVar2 == 0))
        {
            if (*(char*)(param_11 + 0x80) == '\x02')
            {
                iVar2 = FUN_80017a98();
                FUN_80294d40(iVar2, 10);
            }
            uVar1 = 0;
        }
        else
        {
            uVar1 = 1;
        }
    }
    return uVar1;
}


/*
 * --INFO--
 *
 * Function: FUN_8019c318
 * EN v1.0 Address: 0x8019C318
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x8019DAF4
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019c318(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , undefined4 param_10, int param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    uint uVar2;
    short* psVar3;
    uint local_28;
    uint local_24;
    uint local_20[4];

    psVar3 = ((GameObject*)param_9)->extra;
    local_28 = 0;
    while (iVar1 = ObjMsg_Pop(param_9, &local_24, local_20, &local_28), iVar1 != 0)
    {
        if (local_24 == 0x110001)
        {
            if ((*psVar3 == 0x54) && (0xaf < *(short*)(param_11 + 0x58)))
            {
                ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_20[0],
                                    0x110001, param_9, 0, param_13, param_14, param_15, param_16);
            }
        }
        else if ((int)local_24 < 0x110001)
        {
            if (local_24 == 0xa0005)
            {
                param_1 = FUN_80017698((int)*psVar3, 1);
            }
        }
        else if (local_24 == 0x110003)
        {
            if ((*psVar3 == 0x56) && (0xaf < *(short*)(param_11 + 0x58)))
            {
                ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_20[0],
                                    0x110003, param_9, 0, param_13, param_14, param_15, param_16);
            }
        }
        else if ((((int)local_24 < 0x110003) && (*psVar3 == 0x55)) &&
            (0xaf < *(short*)(param_11 + 0x58)))
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_20[0],
                                0x110002, param_9, 0, param_13, param_14, param_15, param_16);
        }
    }
    for (iVar1 = 0; iVar1 < (int)(uint) * (byte*)(param_11 + 0x8b); iVar1 = iVar1 + 1)
    {
        if (((*(char*)(param_11 + iVar1 + 0x81) == '\x01') && (uVar2 = FUN_80017690(0x54), uVar2 != 0))
            && ((uVar2 = FUN_80017690(0x55), uVar2 != 0 && (uVar2 = FUN_80017690(0x56), uVar2 != 0))))
        {
            FUN_80017698(0x4e0, 1);
        }
    }
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_8019d238
 * EN v1.0 Address: 0x8019D238
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x8019E970
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019d238(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    double dVar2;

    iVar1 = *(int*)&((GameObject*)param_9)->extra;
    if ((((GameObject*)param_9)->anim.currentMove != 5) && (((GameObject*)param_9)->anim.currentMove != 0xd))
    {
        FUN_800305f8((double)((GameObject*)param_9)->anim.currentMoveProgress, param_2, param_3, param_4, param_5,
                     param_6, param_7,
                     param_8, param_9, 0xd, 0, param_12, param_13, param_14, param_15, param_16);
    }
    if ((((GameObject*)param_9)->anim.currentMove == 5) && (lbl_803E4EC4 < ((GameObject*)param_9)->anim.velocityY))
    {
        FUN_800305f8((double)((GameObject*)param_9)->anim.currentMoveProgress, param_2, param_3, param_4, param_5,
                     param_6, param_7,
                     param_8, param_9, 0xd, 0, param_12, param_13, param_14, param_15, param_16);
    }
    if ((((GameObject*)param_9)->anim.currentMove == 0xd) && (((GameObject*)param_9)->anim.velocityY < lbl_803E4EB0))
    {
        FUN_800305f8((double)((GameObject*)param_9)->anim.currentMoveProgress, param_2, param_3, param_4, param_5,
                     param_6, param_7,
                     param_8, param_9, 5, 0, param_12, param_13, param_14, param_15, param_16);
    }
    dVar2 = (double)((((GameObject*)param_9)->anim.velocityY * gBoneParticleEffectInterface + lbl_803E4EC8) * lbl_803E4ECC);
    if (dVar2 < (double)lbl_803E4EB0)
    {
        dVar2 = (double)lbl_803E4EB0;
    }
    if ((double)lbl_803E4ECC < dVar2)
    {
        dVar2 = (double)lbl_803E4ECC;
    }
    if (((GameObject*)param_9)->anim.currentMove == 0xd)
    {
        if (((GameObject*)param_9)->anim.currentMoveProgress <= lbl_803E4ECC)
        {
            *(byte*)(iVar1 + 0x244) = *(byte*)(iVar1 + 0x244) & 0xbf;
        }
        else if ((*(byte*)(iVar1 + 0x244) >> 6 & 1) == 0)
        {
            FUN_80006824(param_9, SFXand_spitout);
            *(byte*)(iVar1 + 0x244) = *(byte*)(iVar1 + 0x244) & 0xbf | 0x40;
        }
    }
    FUN_8002fc3c(dVar2, (double)lbl_803DC074);
    return 1;
}


/*
 * --INFO--
 *
 * Function: babycloudrunner_getObjectTypeId
 * EN v1.0 Address: 0x8019EBBC
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801A0A24
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void babycloudrunner_init_OLD_v1_1(int obj)
{
    undefined4* state;

    state = ((GameObject*)obj)->extra;
    *state = 0;
    state[1] = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0x80;
    return;
}

extern f32 lbl_803E422C;
extern f32 lbl_803E4244;
extern f32 lbl_803E4258;
extern u8 lbl_803DBE28;
extern u8 lbl_803DBE30;
extern void storeZeroToFloatParam(void* p);
extern uint GameBit_Get(int eventId);
extern int Obj_RemoveFromUpdateList(int* obj);

typedef struct BabyCloudrunnerFlags
{
    u8 resetLatch : 1;
    u8 flags : 7;
} BabyCloudrunnerFlags;

/* Per-object extra state for the baby CloudRunner
 * (babycloudrunner_getExtraSize == 0x248). */
typedef struct BabyCloudRunnerState
{
    f32 unk00;
    u8 pad04[0x38]; /* 0x18: position used for the sandworm handoff */
    u8 lookBlock[0x30]; /* 0x3c: fn_8003ADC4 head-track block */
    u8 audioBlock[0x3c]; /* 0x6c: objAudioFn block */
    f32 animSpeed;
    f32 scale; /* 0xac: copied to the linked object's scale */
    int unkB0;
    int unkB4;
    int unkB8;
    int unkBC;
    int turnLatch; /* 0xc0: sandworm_turnTowardTargetAnim turn/idle move latch */
    int behaviourState; /* 0xc4: def[0x1c]; SeqFn 0..0xb dispatch */
    u8 padC8[4];
    int unkCC;
    s16 roostYaw; /* 0xd0: heading captured at init */
    u8 padD2[0x42];
    void* linkedObj; /* 0x114 */
    u8 pad118[0xc];
    u8 curveWalker[0x108]; /* 0x124: rom-curve follow block */
    u8 flags22C; /* 1 = alive/active */
    u8 pad22D[3];
    int runnerState; /* 0x230: 0 curve-seek, 1 follow, 2 chased, 3 freed */
    int runnerIndex; /* 0x234: gamebit base index, -1 keyed off */
    f32 countdownTimer; /* 0x238 */
    f32 curveSpeed; /* 0x23c */
    void* mutterSfxTable; /* 0x240 */
    u8 spitFlags; /* 0x244: BabyCloudrunnerFlags / WormSpitByte overlay */
    u8 pad245[3];
} BabyCloudRunnerState;

STATIC_ASSERT(sizeof(BabyCloudRunnerState) == 0x248);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: babycloudrunner_render
 * EN v1.0 Address: 0x8019EC00
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801A0A70
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma peephole reset


/*
 * --INFO--
 *
 * Function: FUN_8019f1dc
 * EN v1.0 Address: 0x8019F1DC
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x801A1190
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019f1dc(void)
{
    uint uVar1;
    int iVar2;
    int* piVar3;
    int iVar4;
    int iVar5;
    int* piVar6;
    int iVar7;
    double in_f29;
    double dVar8;
    double in_f30;
    double dVar9;
    double in_f31;
    double dVar10;
    double in_ps29_1;
    double in_ps30_1;
    double in_ps31_1;
    ulonglong uVar11;
    int local_68;
    ushort local_64[4];
    float local_5c;
    float local_58;
    float local_54;
    float local_50;
    float local_28;
    float fStack_24;
    float local_18;
    float fStack_14;
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    local_18 = (float)in_f30;
    fStack_14 = (float)in_ps30_1;
    local_28 = (float)in_f29;
    fStack_24 = (float)in_ps29_1;
    uVar11 = FUN_8028683c();
    uVar1 = (uint)(uVar11 >> 0x20);
    iVar5 = *(int*)(uVar1 + 0xb8);
    iVar2 = FUN_80017a98();
    iVar2 = *(int*)(iVar2 + 0xb8);
    *(float*)(iVar5 + 0x20) = lbl_803E4F58;
    if ((uVar11 & 0xff) == 0)
    {
        *(float*)(iVar5 + 0x24) = lbl_803E4F6C;
        *(float*)(iVar5 + 0x28) = lbl_803E4F70;
    }
    else
    {
        *(float*)(iVar5 + 0x24) = lbl_803E4F60 * *(float*)(iVar2 + 0x298) + lbl_803E4F5C;
        *(float*)(iVar5 + 0x28) = lbl_803E4F68 * *(float*)(iVar2 + 0x298) + lbl_803E4F64;
    }
    local_58 = lbl_803E4F58;
    local_54 = lbl_803E4F58;
    local_50 = lbl_803E4F58;
    local_5c = lbl_803E4F74;
    local_64[2] = 0;
    local_64[1] = 0;
    local_64[0] = *(ushort*)(iVar5 + 0x50);
    FUN_80017748(local_64, (float*)(iVar5 + 0x20));
    *(byte*)(iVar5 + 0x49) = *(byte*)(iVar5 + 0x49) | 1;
    FUN_80006824(uVar1, SFXsk_baptr6_c);
    *(byte*)(iVar5 + 0x49) = *(byte*)(iVar5 + 0x49) | 2;
    if ((*(byte*)(iVar5 + 0x48) >> 6 & 1) != 0)
    {
        iVar5 = *(int*)(uVar1 + 0x4c);
        iVar2 = 0;
        if (*(short*)(iVar5 + 0x1a) == 0)
        {
            iVar2 = ObjGroup_FindNearestObject(0x3a, uVar1, (float*)0x0);
        }
        else
        {
            piVar3 = ObjGroup_GetObjects(0x3a, &local_68);
            piVar6 = piVar3;
            for (iVar7 = 0; iVar7 < local_68; iVar7 = iVar7 + 1)
            {
                iVar4 = FUN_8020a468(*piVar6);
                if (*(short*)(iVar5 + 0x1a) == iVar4)
                {
                    iVar2 = piVar3[iVar7];
                    break;
                }
                piVar6 = piVar6 + 1;
            }
        }
        if (iVar2 != 0)
        {
            dVar10 = (double)*(float*)(uVar1 + 0xc);
            dVar9 = (double)*(float*)(uVar1 + 0x10);
            dVar8 = (double)*(float*)(uVar1 + 0x14);
            *(undefined4*)(uVar1 + 0xc) = *(undefined4*)(iVar2 + 0xc);
            *(undefined4*)(uVar1 + 0x10) = *(undefined4*)(iVar2 + 0x10);
            *(undefined4*)(uVar1 + 0x14) = *(undefined4*)(iVar2 + 0x14);
            FUN_800e8630(uVar1);
            *(float*)(uVar1 + 0xc) = (float)dVar10;
            *(float*)(uVar1 + 0x10) = (float)dVar9;
            *(float*)(uVar1 + 0x14) = (float)dVar8;
        }
    }
    FUN_80286888();
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void cfguardian_release(void);

void cfguardian_initialise(void);

typedef struct
{
    int a;
    int b;
    s16 c;
} GuardianVec;

extern GuardianVec lbl_802C22C0;
extern GuardianVec lbl_802C22CC;
extern u8 lbl_8032284C[];
extern f32 lbl_803E4110;
extern void dll_2E_func0A(int a, int* obj);
extern void dll_2E_func05(int* obj, u8* sub, int c, int d, int e);
extern void dll_2E_func08(u8* sub, int b, int c);
extern void dll_2E_func09(u8* sub, void* a, void* b, int c);
extern void objSeqInitFn_80080078(u8* p, int n);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

#pragma scheduling off
#pragma peephole off
void cfguardian_init(int* obj, u8* params);
#pragma peephole reset
#pragma scheduling reset

typedef struct
{
    int a, b, c, d;
} GuardianMsg;

extern GuardianMsg lbl_802C22D8;
extern int dll_2E_func07(int* obj, ObjAnimUpdateState* animUpdate, u8* sub, int x, int y);
extern int animatedObjGetSeqId(int* p);
extern void saveGame_saveObjectPos(int obj);
extern void* Obj_GetPlayerObject(void);
extern void playerAddRemoveMagic(void* player, int n);

/* EN v1.0 0x8019C3A0  size: 252b  cfguardian_SeqFn: guardian message handler.
 * Persists position on a negative cue, otherwise picks the active/idle
 * heading pair and routes a move request; on the magic-grant message it
 * tops the player back up. Returns 1 if the move was consumed. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern f32 lbl_803E4218;
extern f32 lbl_803E423C;
extern f32 lbl_803E4240;
extern f32 timeDelta;

/* EN v1.0 0x8019E568  size: 352b  sandworm_turnTowardTargetAnim: turn toward the target by
 * a fraction of the yaw delta; when roughly aligned play/advance the idle
 * move, otherwise start or speed-scale the turn move by the delta. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void sandworm_turnTowardTargetAnim(int* a, int* b, u8* c, int d);
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset


/* EN v1.0 0x801A0614  size: 368b  cfprisoncage_SeqFn: drain the object's message
 * queue (re-arming its gamebit on the keyed message), then sync the
 * lit/active state from gamebit 0x44 and notify on completion. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern f32 Vec_distance(void* a, void* b);
extern f32 s16toFloat(int a, int b);
extern void objAudioFn_800393f8(int obj, void* p, int a, int b, int c, int d);
extern void gameBitIncrement(int bit);
extern void Sfx_PlayFromObject(int obj, int sfxId);

/* EN v1.0 0x8019E6C8  size: 316b  babycloudrunner_func0B: when the player
 * gets within the trigger radius and the runner is in state 3, fire its
 * burst (notify, bump the counter, set the gamebit); otherwise just play
 * the idle audio cue. */
#pragma scheduling off
#pragma peephole off
int babycloudrunner_func0B(void* p);
#pragma peephole reset
#pragma scheduling reset
void windlift_hitDetect(void);

void windlift_release(void);

void windlift_initialise(void);

void cfpowerbase_free(void);

void cfpowerbase_hitDetect(void);

void cfpowerbase_release(void);

void cfpowerbase_initialise(void);

typedef struct
{
    f32 f0, f4, f8, fc, f10, f14;
    u8 b18, b19, b1a, b1b;
} CrystalBeam;

/* Per-object extra state for the CloudRunner main crystal
 * (cfmaincrystal_getExtraSize == 0x160). */
typedef struct CfMainCrystalState
{
    f32 pylonX[3]; /* per-pylon beam source position */
    f32 crystalX;
    f32 pylonY[3];
    f32 crystalY;
    f32 pylonZ[3];
    f32 crystalZ;
    s16 pylonTimer[3]; /* 0x30: 0 unseen; ramps to 0x78 once reported */
    s16 crystalKnown; /* 0x36 */
    CrystalBeam beams[10]; /* 0x38 */
    s16 charge; /* 0x150: convergence charge frames */
    f32 humVolume; /* 0x154 */
    int unk158;
    u8 chime[4]; /* 0x15c: per-beam chime timers */
} CfMainCrystalState;

STATIC_ASSERT(sizeof(CfMainCrystalState) == 0x160);

/* Per-object extra state for the CloudRunner power base
 * (cfpowerbase_getExtraSize == 0x6). */
typedef struct CfPowerBaseState
{
    s16 typeBit; /* gamebit 0x54..0x56, from params+0x1e */
    s16 litBit; /* gamebit 0x51..0x53 gating the lit state */
    s8 typeIndex; /* 0/1/2 trigger argument */
    u8 pad5;
} CfPowerBaseState;

STATIC_ASSERT(sizeof(CfPowerBaseState) == 0x6);

/* Per-object extra state for the CloudRunner prison guard
 * (cfprisonguard_getExtraSize == 0x3c). */
typedef struct CfPrisonGuardState
{
    u8 pad00[0x30];
    f32 alarmRamp; /* particle ramp advanced while above threshold */
    s16 stateTimer;
    s8 capturedLatch; /* last GameBit 0x50 value */
    s8 guardState; /* 0 idle .. 7 forced-chase */
    u8 flags; /* 1 spawn-pulse pending, 2 freed-check, 4 alarm raised */
    u8 flags39; /* 0x80 cleared every update */
    u8 pad3A[2];
} CfPrisonGuardState;

STATIC_ASSERT(sizeof(CfPrisonGuardState) == 0x3c);

/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */
typedef struct CfPrisonUncleState
{
    int target; /* keyed type-0x3d object */
    u8 lookBlock[0x30]; /* fn_8003ADC4 head-track block */
    u8 audioBlock[0x30]; /* objAudioFn block */
    int unk64;
    int unk68;
    u8 pad6C[4];
    s16 unk70;
    u8 pad72;
    s8 captured; /* GameBit 0x4d latch */
    s8 kicked; /* fn_8019FC84 one-shot */
    u8 pad75[0x33];
} CfPrisonUncleState;

STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */
typedef struct GcRobotLightBeaState
{
    void* light; /* modelLightStruct point light */
    int unk4;
    u8 hitFlags; /* 0x80 = player caught in the beam */
    u8 pad9[3];
} GcRobotLightBeaState;

STATIC_ASSERT(sizeof(GcRobotLightBeaState) == 0xc);

/* spiritdoorspirit_getExtraSize == 0x1. */
typedef struct SpiritDoorSpiritState
{
    u8 active; /* gamebit not yet set: render + group 0x4e membership */
} SpiritDoorSpiritState;

#include "main/dll/DR/gunpowderbarrel_state.h"

typedef struct WindliftPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x22 - 0x1C];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} WindliftPlacement;


typedef struct CfprisoncagePlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    u8 pad1A[0x20 - 0x1A];
} CfprisoncagePlacement;


typedef struct GunpowderbarrelLaunchAtTargetPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
} GunpowderbarrelLaunchAtTargetPlacement;


typedef struct SpiritdoorspiritPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} SpiritdoorspiritPlacement;


typedef struct CfguardianState
{
    u8 pad0[0x68C - 0x0];
    void* unk68C;
    u8 pad690[0xA9C - 0x690];
} CfguardianState;


typedef struct BabycloudrunnerObjectDef
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} BabycloudrunnerObjectDef;


typedef struct CfmaincrystalObjectDef
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} CfmaincrystalObjectDef;


typedef struct CfprisoncageObjectDef
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} CfprisoncageObjectDef;


typedef struct WindliftObjectDef
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    s16 delay;
    s16 seqId;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} WindliftObjectDef;


typedef struct CfprisonguardPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} CfprisonguardPlacement;


typedef struct BabycloudrunnerPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} BabycloudrunnerPlacement;


/* EN v1.0 0x8019D8B4  size: 308b  cfpowerbase_init: seed header and the
 * sub's type from spawn params, map the type id (0x54..0x56) to a model
 * and gamebit, then gate the active/lit state bits on those gamebits. */
#pragma scheduling off
#pragma peephole off
void cfpowerbase_init(int* obj, u8* params);
#pragma peephole reset
#pragma scheduling reset


/* EN v1.0 0x8019D77C  size: 312b  cfpowerbase_update: track its gamebit's
 * lit state, fire the queued state-change trigger, and when the base is
 * powered and its UI condition clears, mark it done and notify. */
#pragma scheduling off
#pragma peephole off
void cfpowerbase_update(int* obj);
#pragma peephole reset
#pragma scheduling reset
void cfmaincrystal_hitDetect(void);

void cfmaincrystal_release(void);

void cfmaincrystal_initialise(void);

void babycloudrunner_hitDetect(void);

void babycloudrunner_release(void);

void babycloudrunner_initialise(void);

void cfprisonguard_free(void);

void cfprisonguard_release(void);

void cfprisonguard_initialise(void);

typedef struct
{
    u8 top : 1;
    u8 rest : 7;
} Bit80;

/* EN v1.0 0x8019FBD0  size: 172b  cfprisonguard_init: set up the guard's
 * substate (update fn cfprisonguard_SeqFn, message queue), seed its header from
 * the spawn params, and apply the alarm-active gating bits. */
#pragma scheduling off
#pragma peephole off
void cfprisonguard_init(int* obj, u8* params);
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E4268;
extern int waterfx_consumePendingImpactNearPoint(f32* vec, f32 r);
extern int objGetAnimState80A(void* obj);

#pragma scheduling off
#pragma peephole off
void cfprisonguard_update(int* obj);
#pragma peephole reset
#pragma scheduling reset
void cfprisonuncle_free(void);

void cfprisonuncle_hitDetect(void);

void cfprisonuncle_release(void);

void cfprisonuncle_initialise(void);

extern int objModelGetVecFn_800395d8(int obj, int idx);
extern void objAudioFn_80039270(int obj, void* p, int id);
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern u8 framesThisStep;
extern f32 lbl_803E428C;

/* EN v1.0 0x8019FEDC  size: 536b  cfprisonuncle_update: while not captured,
 * drain pending messages, re-acquire the keyed target object, then either
 * track/animate toward the player (firing the alert trigger) or, once
 * captured, raise the done flag and notify. */
#pragma scheduling off
#pragma peephole off
void cfprisonuncle_update(int* obj);
#pragma peephole reset
#pragma scheduling reset
void gcrobotlightbea_render(void);

void gcrobotlightbea_release(void);

void gcrobotlightbea_initialise(void);

extern f32 lbl_803E4298;

/* EN v1.0 0x801A01E8  size: 296b  gcrobotlightbea_hitDetect: clear the hit
 * flag, then re-set it only if the priority hit is the (undisguised) player
 * and lands inside the beacon's bounding box. */
#pragma scheduling off
#pragma peephole off
void gcrobotlightbea_hitDetect(int* obj);
#pragma peephole reset
#pragma scheduling reset
void cfperch_render(void)
{
}

void cfperch_hitDetect(void)
{
}

void cfperch_release(void)
{
}

void cfperch_initialise(void)
{
}

void cfprisoncage_free(void);

void cfprisoncage_release(void);

void cfprisoncage_initialise(void);

#pragma scheduling off
#pragma peephole off
void cfprisoncage_update(int* obj);
#pragma peephole reset
#pragma scheduling reset
void spiritdoorspirit_hitDetect(void);

void spiritdoorspirit_release(void);

void spiritdoorspirit_initialise(void);

/* 8b "li r3, N; blr" returners. */
int cfguardian_getExtraSize(void);
int cfguardian_getObjectTypeId(void);
int windlift_getExtraSize(void);
int windlift_getObjectTypeId(void);
int cfpowerbase_getExtraSize(void);
int cfpowerbase_getObjectTypeId(void);
int cfmaincrystal_getExtraSize(void);
int cfmaincrystal_getObjectTypeId(void);
int babycloudrunner_getExtraSize(void);
int cfprisonguard_getExtraSize(void);
int cfprisonguard_getObjectTypeId(void);
int cfprisonuncle_getExtraSize(void);
int cfprisonuncle_getObjectTypeId(void);
int gcrobotlightbea_getExtraSize(void);
int gcrobotlightbea_getObjectTypeId(void);
int cfperch_getExtraSize(void) { return 0x0; }
int cfperch_getObjectTypeId(void) { return 0x0; }
int cfprisoncage_getExtraSize(void);
int spiritdoorspirit_getExtraSize(void);
int spiritdoorspirit_getObjectTypeId(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4190;
extern f32 lbl_803E41D0;
extern f32 lbl_803E4210;
extern f32 lbl_803E42B0;
#pragma peephole off
void windlift_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void cfpowerbase_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void cfmaincrystal_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void cfprisoncage_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset

extern f32 lbl_803E4280;
extern f32 lbl_803E4260;
extern f32 lbl_803E4264;
extern f32 lbl_803E4284;
extern void objParticleFn_80099d84(int obj, f32 f, int a, int b);

/* EN v1.0 0x8019F93C  size: 188b  cfprisonguard_render: render the guard
 * model when visible, ramp its alarm timer at sub->_30 each frame, and
 * once it crosses the threshold spawn a one-shot particle. */
#pragma scheduling off
#pragma peephole off
void cfprisonguard_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset
#pragma scheduling reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
void spiritdoorspirit_free(int x);
#pragma scheduling reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
int cfprisoncage_getObjectTypeId(int* obj);
#pragma peephole reset

/* chained byte bit-extract. */
u32 fn_801A0174(int* obj);

typedef struct
{
    u8 playerHeld : 1;
    u8 _pad0 : 1;
    u8 held : 1;
    u8 _pad1 : 5;
} GpbHeldByte;

extern f32 lbl_803E42C0;


/* state-transition: kicks player into mode 2 when sandworm not yet eaten. */
#pragma peephole off
int fn_8019FC84(int* obj, int unused, ObjAnimUpdateState* animUpdate);
#pragma peephole reset

/* GameBit-gated byte write. */
#pragma scheduling off
int fn_801A04F4(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (GameBit_Get(0x4d) != 0)
    {
        animUpdate->sequenceControlFlags = 4;
    }
    return 0;
}
#pragma scheduling reset

/* plain forwarder. */
extern int waterSpellStone1Fn_8019b4c8();
void cfguardian_update(void);

/* Drift-recovery: add new fns with v1.0 names. */
extern f32 lbl_803E42B8;
extern f32 lbl_803E4130;
extern f32 lbl_803E416C;
extern void modelLightStruct_freeSlot(int* p);
/* ObjLink_DetachChild already declared above as undefined4 ObjLink_DetachChild() */
extern void dll_2E_func06(int* a, int* b, int c);
extern void objfx_spawnHitEmitterAtPos(f32* p, int a, int b, int c, int d);
extern f32 fn_80296214(void* p);
/* ObjMsg_AllocQueue already declared as undefined */
extern void Music_Trigger(int a, int b);
extern int ObjHits_GetPriorityHitWithPosition(int* obj, int a, int b, int c, f32* out_x, f32* out_y, f32* out_z);

#pragma scheduling off
#pragma peephole off


void spiritdoorspirit_init(int* obj);

extern f32 lbl_803DBE78;
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);

void spiritdoorspirit_update(int* obj);

int babycloudrunner_setScale(int* obj);

void cfperch_init(int* obj)
{
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = (void*)fn_801A04F4;
}

void cfmaincrystal_free(int* obj);

void cfperch_free(int* obj)
{
    ObjMsg_SendToObjects(62, 0, obj, 0x40001, 0);
}

void babycloudrunner_free(int* obj);

void gcrobotlightbea_init(int* obj);

extern f32 lbl_803E42A0;
extern f32 lbl_803E42A4;
extern f32 lbl_80322C38[];
extern f32 lbl_803DBE58;
extern f32 lbl_803DBE5C;
extern void* modelLightStruct_createPointLight(int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(void* light, f32 a, f32 b);
extern void modelLightStruct_setPosition(void* light, f32 x, f32 y, f32 z);
extern void Obj_TransformLocalVectorByWorldMatrix(int* obj, void* out, void* in);
extern void voxmaps_traceScaledVectorEnd(f32* dst, void* posA, f32* dir, f32 factor);
extern f32 PSVECDistance(void* a, void* b);
extern void PSVECScale(void* in, void* out, f32 scale);
extern void getAmbientColor(int mode, u8* r, u8* g, u8* b);
extern void modelLightStruct_setDiffuseColor(void* p, int r, int g, int b, int a);

void gcrobotlightbea_update(int* obj);

void spiritdoorspirit_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void cfprisonguard_hitDetect(int* obj);

void gcrobotlightbea_free(int* obj);

void cfguardian_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void cfprisoncage_hitDetect(int* obj);

extern f32 lbl_803E42B4;

void cfprisoncage_init(int* obj, u8* def);

void windlift_free(int* obj);

void cfguardian_free(int* obj, int p2);


void cfprisonuncle_init(int* obj);

#pragma peephole reset
#pragma scheduling reset

/* copy 3 floats within same struct */
void cfguardian_hitDetect(int* obj);

#pragma scheduling off
#pragma dont_inline on
int* findRomCurvePointNearObject(int* obj, int p2, int* outVec, int p4);
#pragma dont_inline reset
#pragma scheduling reset

extern void fn_8019D9F0(int* obj);
extern int* lbl_803DDB10;
#pragma peephole off
#pragma scheduling off
void cfmaincrystal_update(int* obj);
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cfperch_update(int* obj)
{
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (GameBit_Get(0x50) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
    ((GameObject*)obj)->unkF4 = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cfmaincrystal_init(int* obj, u8* def);
#pragma peephole reset
#pragma scheduling reset

extern void vecRotateZXY(s16 * rotIn, f32 * outVec);
extern int barrelgener_getLinkId(int barrel);
extern f32 lbl_803E42C4;
extern f32 lbl_803E42C8;
extern f32 lbl_803E42CC;
extern f32 lbl_803E42D0;
extern f32 lbl_803E42D4;
extern f32 lbl_803E42D8;
extern f32 lbl_803E42DC;


extern f32 lbl_803E4230;
extern f32 lbl_803E4234;
extern f32 lbl_803DBE4C;

typedef struct
{
    u8 _p0 : 1;
    u8 spitLatch : 1;
    u8 _p1 : 6;
} WormSpitByte;

/* EN v1.0 0x8019E3F4  size: 372b  fn_8019E3F4: pick the burrow/surface move
 * from the vertical speed, clamp the playback rate, latch the spit SFX
 * while surfacing fast, and advance the current move. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
int fn_8019E3F4(int* obj);
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern int objUpdateOpacity(int sub);
extern f32 lbl_803E4288;

/* EN v1.0 0x8019FCF4  size: 484b  cfprisonuncle_render: render the uncle and/or
 * his held model depending on the rescue gamebits, opacity and visibility;
 * when path-following, snap the held model to the path point first. */
#pragma scheduling off
#pragma peephole off
void cfprisonuncle_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset
#pragma scheduling reset

extern f32 sqrtf(f32 x);
extern void normalize(f32 * x, f32 * y, f32 * z);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern f32 lbl_803E4124;
extern f32 lbl_803E4128;

/* EN v1.0 0x8019B1D8  size: 544b  fn_8019B1D8: steer the object toward the
 * target: scale its velocity along the normalized delta, blend the yaw by
 * speed over distance, move it and keep the chase move playing. Returns 1
 * when already within the closing threshold. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int fn_8019B1D8(int* obj, int* target, f32 speed, int p4);
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern int seqStreamLookupFn_8007fff8(void* table, int count, int key);
extern u8 lbl_80322A48[];
extern u8 lbl_80322A68[];
extern f32 lbl_803E41C8;
extern f32 lbl_803E41CC;
extern f32 lbl_803E4168;

typedef struct
{
    int i0;
    f32 f4;
    f32 f8;
    f32 fc;
    u8 b10;
    u8 b11;
    u8 pad12[2];
    int link14;
} WindLiftSlot;

typedef struct
{
    int duration;
    int seqId;
    int delay;
    int gamebit;
    int pad10;
    int timer;
    WindLiftSlot slots[14];
    int pad168;
    int pad16c;
    f32 liftHeight;
    u8 musicOn : 1;
    u8 active : 1;
    u8 _f2 : 6;
} WindLiftSub;

/* EN v1.0 0x8019D2AC  size: 708b  windlift_init: look up the lift's sequence
 * timings, scale its rise height from the def byte, arm it from the
 * gamebits and clear all 14 rider slots. */
#pragma scheduling off
#pragma peephole off
void windlift_init(int* obj, u8* def);
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E42E0;
extern f32 lbl_803E42E4;
extern const f32 lbl_803E42E8;
extern f32 lbl_803E42EC;
extern f32 lbl_803E42F0;


extern void* getTrickyObject(void);
extern f32 lbl_803E4248;

/* EN v1.0 0x8019E81C  size: 920b  babycloudrunner_SeqFn: range-check the
 * runner against the player and its trigger radii, chirp for queued cues,
 * then steer toward the player (or Tricky) per the current behaviour state. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern void Sfx_StopObjectChannel(int obj, int ch);


/* EN v1.0 0x8019F540  size: 1000b  cfprisonguard_SeqFn: drive the guard state
 * machine - ramp/reset the alarm on cues, bail when captured or freed, watch
 * the player distance/water impacts and chase or stand down, with idle digging
 * SFX and queued-message drain. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern f32 Vec_xzDistance(void* a, void* b);
extern void fn_80296220(int* rider, f32 v);
extern f32 lbl_803E4170;
extern f32 lbl_803E4174;
extern f32 lbl_803E4178;
extern f32 lbl_803E417C;
extern f32 lbl_803E4180;
extern f32 lbl_803E4184;
extern f32 lbl_803E4188;
extern f32 lbl_803E418C;
extern f32 lbl_803E4194;
extern f32 lbl_803E4198;
extern f32 lbl_803E419C;
extern f32 lbl_803E41A0;
extern f32 lbl_803E41A4;
extern f32 lbl_803E41A8;
extern f32 lbl_803E41AC;
extern f32 lbl_803E41B0;
extern f32 lbl_803E41B4;
extern f32 lbl_803E41B8;

/* EN v1.0 0x8019C784  size: 1396b  fn_8019C784: per-rider wind lift physics -
 * track the rider while above the lift and in range, send the lift/drop
 * messages on state edges, and integrate the rise speed with ramp-up,
 * oscillation damping and player-mode handoff. */
#pragma scheduling off
#pragma peephole off
void fn_8019C784(int* obj, int* rider, WindLiftSlot* slot, f32 pull, int gb, int pm, uint dur, f32 height);
#pragma peephole reset
#pragma scheduling reset

extern int Obj_SetActiveModelIndex(int* obj, int idx);
extern f32 lbl_803E41BC;

/* EN v1.0 0x8019CD98  size: 1300b  windlift_update: fade the lift opacity
 * with its gamebit, spin up over the first second, then assign every nearby
 * group-0x16 object (and the player) to a rider slot and run the lift
 * physics on each. */
#pragma scheduling off
#pragma peephole off
void windlift_update(int* obj);
#pragma peephole reset
#pragma scheduling reset

extern int fn_80080150(void* p);
extern int timerCountDown(void* p);
extern int randFn_80080100(int n);
extern void Obj_UpdateRomCurveFollowVelocity(int* obj, void* p, f32 a, f32 b, f32 c, int d);
extern void Obj_SmoothTurnAnglesTowardVelocity(int* obj, void* p, int n, f32 a, f32 b);
extern void fn_8014C66C(int* a, void* b);
extern int dll_2E_func0D(int* obj, void* p, f32 f, int c, f32* a, f32* b);
extern int lbl_80322B28[];
extern f32 lbl_803DBE38;
extern f32 lbl_803DBE3C;
extern f32 lbl_803DBE40;
extern f32 lbl_803DBE44;
extern f32 lbl_803DBE48;
extern f32 lbl_803E4238;
extern f32 lbl_803E424C;
extern f32 lbl_803E4250;
extern f32 lbl_803E4254;

typedef struct
{
    s16 a, b, c;
    u8 pad[6];
    f32 x, y, z;
} RunnerTarget;

/* EN v1.0 0x8019EC34  size: 1908b  babycloudrunner_update: full runner brain -
 * despawn on its gamebit, run the captured/timer flow, follow its rom curve
 * while fleeing, hand off to the nearest sandworm, and once freed steer home
 * to the roost point. */
#pragma scheduling off
#pragma peephole off
void babycloudrunner_update(int* obj);
#pragma peephole reset
#pragma scheduling reset

extern void getEnvfxAct(int a, int b, int c, int d);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int ch);
extern void Sfx_SetObjectChannelVolume(int obj, int ch, int max, f32 vol);
extern void PSVECNormalize(f32 * out, f32 * in);
extern f32 lbl_803E41D8;
extern f32 lbl_803E41DC;
extern f32 lbl_803E41E0;
extern f32 lbl_803E41E4;
extern f32 lbl_803E41E8;
extern f32 lbl_803E41EC;
extern f32 lbl_803E41F0;
extern f32 lbl_803E41F4;
extern f32 lbl_803E41F8;
extern f32 lbl_803E41FC;
extern f32 lbl_803E4200;
extern f32 lbl_803E4204;

extern void Camera_EnableViewYOffset(void);

typedef struct
{
    s16 a, b, c, d;
    u8 pad[4];
    f32 x, y, z;
} PartPayload;

/* EN v1.0 0x8019D9F0  size: 2112b  fn_8019D9F0: main crystal beam update -
 * collect the three pylon positions from messages, re-request missing ones,
 * emit the beam particles toward the crystal (and down from each pylon),
 * ramp the convergence charge, hum volume and per-beam chime timers. */
#pragma scheduling off
#pragma peephole off
void fn_8019D9F0(int* obj);
#pragma peephole reset
#pragma scheduling reset

extern int fn_8019AF64(int* obj, void* path, f32 f, int phase, void* spd);
extern void fn_8019AE3C(int* obj, void* evbuf, void* p);
extern int fn_80296A14(int p);
extern void dll_2E_func04(void* sub);
extern void dll_2E_func0C(int a, void* p);
extern void buttonDisable(int a, int b);
extern void characterDoEyeAnims(int* obj, void* p);
extern int hitDetectFn_800658a4(int* obj, f32 x, f32 y, f32 z, f32* out, int p);
extern int lbl_80322954[];
extern u8 lbl_803DBE20;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E4134;
extern f32 lbl_803E4138;
extern f32 lbl_803E413C;
extern f32 lbl_803E4140;
extern f32 lbl_803E4144;
extern f32 lbl_803E4148;
extern f32 lbl_803E414C;
extern f32 lbl_803E4150;
extern f32 lbl_803E4154;
extern f32 lbl_803E4158;
extern f32 lbl_803E415C;
extern f32 lbl_803E412C;

/* EN v1.0 0x8019B4C8  size: 3800b  waterSpellStone1Fn_8019b4c8: cfguardian
 * brain - sixteen-state quest progression for the CloudRunner guardian, with
 * sandworm avoidance, path flights, landing physics, sequenced triggers and
 * idle chatter. */
#pragma scheduling off
#pragma peephole off
int waterSpellStone1Fn_8019b4c8(int* obj);
#pragma peephole reset
#pragma scheduling reset
