/*
 * sandwormBoss.c — 10-DLL container (DLL 0x14A CFPowerBase .. 0x157
 * SpiritDoorSpirit), TU [8019D578-801A0B14). DLLs 0x148 and 0x149 are
 * defined in dll_0148_cfguardian.c and dll_0149_cfwindlift.c; their
 * definitions here are collapsed to forward prototypes.
 */
#include "main/dll/cfguardian_state.h"
#include "main/dll/bit80_struct.h"
#include "main/dll/wormspitbyte_struct.h"
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/dll/babycloudrunnerflags_struct.h"
#include "main/dll/gcrobotlightbeastate_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

extern undefined4 getLActions();
extern undefined8 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern void objRenderFn_8003b8f4(f32);
extern undefined4 FUN_8006f7a0();
extern int FUN_8007f924();
extern undefined4 FUN_800e8630();
extern int FUN_801149b8();
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
extern f64 DOUBLE_803e4db0;
extern f32 lbl_803DC074;
extern f32 gBoneParticleEffectInterface;
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

undefined4
FUN_8019b650(undefined8 param_1, double param_2, double param_3, double param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* param_9,
             undefined4 param_10, undefined4 param_11, float* param_12, int param_13, undefined4 param_14
             , undefined4 param_15, undefined4 param_16)
{
    return 0;
}

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
extern uint GameBit_Get(int eventId);
extern int Obj_RemoveFromUpdateList(int* obj);

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

void cfguardian_release(void);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

extern void* Obj_GetPlayerObject(void);

extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);

extern f32 Vec_distance(void* a, void* b);
extern void Sfx_PlayFromObject(int obj, int sfxId);

/* Per-object extra state for the CloudRunner main crystal
 * (cfmaincrystal_getExtraSize == 0x160). */

STATIC_ASSERT(sizeof(CfMainCrystalState) == 0x160);

/* Per-object extra state for the CloudRunner power base
 * (cfpowerbase_getExtraSize == 0x6). */

STATIC_ASSERT(sizeof(CfPowerBaseState) == 0x6);

/* Per-object extra state for the CloudRunner prison guard
 * (cfprisonguard_getExtraSize == 0x3c). */

STATIC_ASSERT(sizeof(CfPrisonGuardState) == 0x3c);

/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */

STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */

STATIC_ASSERT(sizeof(GcRobotLightBeaState) == 0xc);

/* spiritdoorspirit_getExtraSize == 0x1. */

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

void cfprisonguard_free(void)
{
}

void cfprisonguard_release(void)
{
}

void cfprisonguard_initialise(void)
{
}

/* EN v1.0 0x8019FBD0  size: 172b  cfprisonguard_init: set up the guard's
 * substate (update fn cfprisonguard_SeqFn, message queue), seed its header from
 * the spawn params, and apply the alarm-active gating bits. */
#pragma scheduling off
#pragma peephole off
void cfprisonguard_init(int* obj, u8* params)
{
    CfPrisonGuardState* sub = ((GameObject*)obj)->extra;
    sub->flags = 1;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = (void*)cfprisonguard_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    sub->capturedLatch = 1;
    if (GameBit_Get(0x4d) != 0)
    {
        sub->flags = (u8)(sub->flags | 4);
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x10);
    ((Bit80*)&sub->flags39)->top = 1;
}

extern f32 lbl_803E4268;
extern int waterfx_consumePendingImpactNearPoint(f32* vec, f32 r);
extern int objGetAnimState80A(void* obj);

void cfprisonguard_update(int* obj)
{
    CfPrisonGuardState* sub;
    int* player;
    u8* def;
    int bit44;
    f32 dist;

    sub = ((GameObject*)obj)->extra;
    player = (int*)Obj_GetPlayerObject();
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((u32)sub->flags39 >> 7) & 1u)
    {
        sub->flags39 = (u8)(sub->flags39 & ~0x80);
    }
    if (GameBit_Get(((CfprisonguardPlacement*)def)->unk1E) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | 0x4000);
        ObjHits_DisableObject(obj);
        Obj_RemoveFromUpdateList(obj);
        return;
    }
    bit44 = GameBit_Get(0x44);
    dist = Vec_distance((char*)obj + 0x18, (char*)player + 0x18);
    if (sub->flags == 1)
    {
        waterfx_consumePendingImpactNearPoint(&((GameObject*)obj)->anim.localPosX, lbl_803E4268);
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        sub->flags = 2;
    }
    if (bit44 == 0)
    {
        if (sub->guardState != 4)
        {
            if (dist >= (f32)(s32)((CfprisonguardPlacement*)def)->unk1A)
            {
                if (waterfx_consumePendingImpactNearPoint(&((GameObject*)obj)->anim.localPosX, lbl_803E4268) == 0)
                    return;
            }
        }
        if (objGetAnimState80A(player) != 0x40)
        {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        }
    }
}
void cfprisonuncle_free(void);

extern u8 framesThisStep;

int cfprisonguard_getExtraSize(void) { return 0x3c; }
int cfprisonguard_getObjectTypeId(void) { return 0x49; }
int cfprisonuncle_getExtraSize(void);

extern f32 lbl_803E4280;
extern f32 lbl_803E4260;
extern f32 lbl_803E4264;
extern f32 lbl_803E4284;
extern void objParticleFn_80099d84(int obj, f32 f, int a, int b);

/* EN v1.0 0x8019F93C  size: 188b  cfprisonguard_render: render the guard
 * model when visible, ramp its alarm timer at sub->_30 each frame, and
 * once it crosses the threshold spawn a one-shot particle. */
void cfprisonguard_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CfPrisonGuardState* sub = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E4280);
    }
    if (visible != 0)
    {
        f32 t = sub->alarmRamp;
        if (t > lbl_803E4260)
        {
            sub->alarmRamp = lbl_803E4264 * (f32)(u32)
            framesThisStep + t;
            if (sub->alarmRamp < lbl_803E4284)
            {
                objParticleFn_80099d84((int)obj, lbl_803E4280, 3, 0);
            }
        }
    }
}

void cfprisonguard_hitDetect(int* obj)
{
    CfPrisonGuardState* state = ((GameObject*)obj)->extra;
    if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) == 19)
    {
        state->guardState = 7;
    }
}

void gcrobotlightbea_free(int* obj);

extern void Sfx_StopObjectChannel(int obj, int ch);

/* EN v1.0 0x8019F540  size: 1000b  cfprisonguard_SeqFn: drive the guard state
 * machine - ramp/reset the alarm on cues, bail when captured or freed, watch
 * the player distance/water impacts and chase or stand down, with idle digging
 * SFX and queued-message drain. */
int cfprisonguard_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* player;
    CfPrisonGuardState* sub = ((GameObject*)obj)->extra;
    s8 gb50;
    s8 gb48;
    s8 moved;
    f32 dist;
    int msgB;
    int msgA;
    int payload = 0;
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    switch (animUpdate->triggerCommand)
    {
    case 0x29:
        sub->alarmRamp = lbl_803E4260;
        break;
    case 4:
        sub->guardState = 6;
        return 0;
    case 5:
        sub->alarmRamp = lbl_803E4264 * (f32)framesThisStep + sub->alarmRamp;
        break;
    }
    if (((GameObject*)obj)->seqIndex < 0)
    {
        return 0;
    }
    ObjHits_EnableObject(obj);
    gb50 = GameBit_Get(0x50);
    gb48 = GameBit_Get(0x48);
    if ((sub->flags & 2) != 0 && GameBit_Get(0x4d) != 0)
    {
        sub->flags &= ~0x2;
        return 4;
    }
    if (gb50 != 0)
    {
        return 4;
    }
    if (gb50 != 0 || sub->guardState == 5)
    {
        sub->guardState = 5;
        return 0;
    }
    moved = 0;
    player = (char*)Obj_GetPlayerObject();
    switch (sub->guardState)
    {
    case 0:
        fn_8003B228(obj, sub);
        dist = Vec_distance((char*)obj + 0x18, player + 0x18);
        if (gb48 == 0)
        {
            if (dist < (f32)((CfprisonguardPlacement*)def)->unk1A
                || waterfx_consumePendingImpactNearPoint(&((GameObject*)obj)->anim.localPosX, lbl_803E4268) != 0)
            {
                if (objGetAnimState80A(player) != 0x40)
                {
                    moved = 1;
                    sub->guardState = 4;
                }
                else
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                    sub->guardState = 5;
                    sub->stateTimer = 0x14;
                    (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                    return 4;
                }
            }
        }
        break;
    case 2:
        if ((sub->stateTimer -= framesThisStep) <= 0)
        {
            sub->guardState = 1;
        }
        fn_8003B228(obj, sub);
        break;
    case 1:
        dist = Vec_distance((char*)obj + 0x18, player + 0x18);
        if (gb48 == 0)
        {
            if (dist < (f32)((CfprisonguardPlacement*)def)->unk1A)
            {
                if (objGetAnimState80A(player) != 0x40)
                {
                    moved = 1;
                    sub->guardState = 4;
                }
                else
                {
                    sub->guardState = 2;
                }
            }
        }
        break;
    case 3:
        if ((sub->stateTimer -= framesThisStep) <= 0)
        {
            sub->guardState = 0;
        }
        break;
    case 5:
        return 0;
    case 6:
        return 0;
    case 7:
        moved = 1;
        sub->guardState = 4;
        break;
    }
    if (((GameObject*)obj)->anim.currentMove == 0x103 || ((GameObject*)obj)->anim.currentMove == 0x2e)
    {
        Sfx_PlayFromObject((int)obj, SFXsk_doggydig11);
    }
    else
    {
        Sfx_StopObjectChannel((int)obj, 0x10);
    }
    if (gb50 != 0 && sub->capturedLatch == 0)
    {
        moved = 1;
    }
    if (moved != 0)
    {
        return 4;
    }
    sub->capturedLatch = gb50;
    animUpdate->sequenceEventActive = 0;
    while (ObjMsg_Pop(obj, &msgA, &msgB, &payload) != 0)
    {
    }
    if (animUpdate->triggerCommand == 1)
    {
        getLActions(obj, obj, 0x18, 0, 0, 0);
        animUpdate->triggerCommand = 0;
    }
    return 0;
}

extern f32 Vec_xzDistance(void* a, void* b);
