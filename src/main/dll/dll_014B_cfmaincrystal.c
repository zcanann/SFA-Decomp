/* DLL 0x014B — cfmaincrystal. TU: 0x8019D9F0–0x8019E3F4. */
#include "main/dll/cfguardian_state.h"
#include "main/dll/wormspitbyte_struct.h"
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/dll/babycloudrunnerflags_struct.h"
#include "main/dll/gcrobotlightbeastate_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

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
extern undefined4 ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern int ObjMsg_Pop();
extern undefined8 ObjMsg_SendToObjects();
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
extern EffectInterface** gPartfxInterface;
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

/* Trivial 4b 0-arg blr leaves. */
void cfguardian_release(void);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

extern void* Obj_GetPlayerObject(void);

extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);

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

void cfmaincrystal_hitDetect(void)
{
}

void cfmaincrystal_release(void)
{
}

void cfmaincrystal_initialise(void)
{
}

void babycloudrunner_hitDetect(void);

extern u8 framesThisStep;

/* 8b "li r3, N; blr" returners. */
int cfmaincrystal_getExtraSize(void) { return 0x160; }
int cfmaincrystal_getObjectTypeId(void) { return 0x1; }
int babycloudrunner_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4210;

#pragma peephole off
void cfmaincrystal_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4210);
}

void cfprisoncage_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* chained byte bit-extract. */

/* plain forwarder. */

/* Drift-recovery: add new fns with v1.0 names. */
/* ObjLink_DetachChild already declared above as undefined4 ObjLink_DetachChild() */
/* ObjMsg_AllocQueue already declared as undefined */

#pragma scheduling off
void cfmaincrystal_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void cfperch_free(int* obj);

extern void fn_8019D9F0(int* obj);
extern int* lbl_803DDB10;
void cfmaincrystal_update(int* obj)
{
    uint payload;
    uint msgType;
    uint srcObjId;
    s8 t;
    t = ((s8*)*(int*)&((GameObject*)obj)->anim.placementData)[0x19];
    switch (t)
    {
    case 0:
        fn_8019D9F0(obj);
        break;
    case 1:
        payload = 0;
        while (ObjMsg_Pop(obj, &msgType, &srcObjId, &payload) != 0)
        {
            if (msgType == 0x110004)
            {
                ObjMsg_SendToObject((void*)srcObjId, 0x110004, obj, 0);
            }
        }
        lbl_803DDB10 = obj;
        *(s16*)obj = (s16)(*(s16*)obj + (s32)framesThisStep * 0xb6);
        break;
    }
}

void cfmaincrystal_init(int* obj, u8* def)
{
    CfMainCrystalState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32) * (s8*)((char*)def + 0x18) << 8);
    if (*(s8*)((char*)def + 0x19) == 0)
    {
        state->chime[0] = 0x28;
        state->chime[1] = 0;
        state->chime[2] = 0;
        state->chime[3] = 0x46;
        ((ObjAnimComponent*)obj)->bankIndex = 1;
        state->unk158 = 0;
    }
    ObjMsg_AllocQueue(obj, 2);
}

extern void vecRotateZXY(s16 * rotIn, f32 * outVec);

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
void fn_8019D9F0(int* obj)
{
    char* p16;
    char* p32;
    int i;
    CfMainCrystalState* sub = ((GameObject*)obj)->extra;
    int idx;
    int count;
    PartPayload pay;
    f32 dir[3];
    int msgSrc;
    int msgType;
    int payload = 0;
    Obj_GetPlayerObject();
    Camera_EnableViewYOffset();
    while (ObjMsg_Pop(obj, &msgType, &msgSrc, &payload) != 0)
    {
        switch (msgType)
        {
        case 0x110001:
            sub->pylonX[0] = *(f32*)((char*)msgSrc + 0xc);
            sub->pylonY[0] = lbl_803E41D8;
            sub->pylonZ[0] = *(f32*)((char*)msgSrc + 0x14);
            sub->pylonTimer[0] = 1;
            break;
        case 0x110002:
            sub->pylonX[1] = *(f32*)((char*)msgSrc + 0xc);
            sub->pylonY[1] = lbl_803E41D8;
            sub->pylonZ[1] = *(f32*)((char*)msgSrc + 0x14);
            sub->pylonTimer[1] = 1;
            break;
        case 0x110003:
            sub->pylonX[2] = *(f32*)((char*)msgSrc + 0xc);
            sub->pylonY[2] = lbl_803E41D8;
            sub->pylonZ[2] = *(f32*)((char*)msgSrc + 0x14);
            sub->pylonTimer[2] = 1;
            break;
        case 0x110004:
            sub->crystalX = *(f32*)((char*)msgSrc + 0xc);
            sub->crystalY = *(f32*)((char*)msgSrc + 0x10);
            sub->crystalZ = *(f32*)((char*)msgSrc + 0x14);
            sub->crystalKnown = 1;
            break;
        }
    }
    if (sub->crystalKnown == 0)
    {
        ObjMsg_SendToObjects(0xdc, 5, obj, 0x110004, 0);
    }
    if (GameBit_Get(0x54) != 0 && sub->pylonTimer[0] == 0)
    {
        ObjMsg_SendToObjects(0xda, 4, obj, 0x110001, 0);
    }
    if (GameBit_Get(0x55) != 0 && sub->pylonTimer[1] == 0)
    {
        ObjMsg_SendToObjects(0xda, 4, obj, 0x110002, 0);
    }
    if (GameBit_Get(0x56) != 0 && sub->pylonTimer[2] == 0)
    {
        ObjMsg_SendToObjects(0xda, 4, obj, 0x110003, 0);
    }
    sub->beams[0].b1b = 0;
    sub->beams[1].b1b = 0;
    sub->beams[2].b1b = 0;
    sub->beams[3].b1b = 0;
    sub->beams[4].b1b = 0;
    sub->beams[5].b1b = 0;
    sub->beams[6].b1b = 0;
    sub->beams[7].b1b = 0;
    sub->beams[8].b1b = 0;
    sub->beams[9].b1b = 0;
    count = 0;
    idx = 0;
    if (sub->crystalKnown != 0)
    {
        if (GameBit_Get(0x57) != 0)
        {
            if (sub->pylonTimer[0] != 0)
            {
                sub->pylonTimer[0] = 0x78;
            }
            if (sub->pylonTimer[1] != 0)
            {
                sub->pylonTimer[1] = 0x78;
            }
            if (sub->pylonTimer[2] != 0)
            {
                sub->pylonTimer[2] = 0x78;
            }
            sub->charge = 0x5a;
        }
        i = 0;
        p16 = (char*)sub;
        p32 = (char*)sub;
        do
        {
            if (i < 3 && *(s16*)(p16 + 0x30) != 0)
            {
                CrystalBeam* sl = &sub->beams[idx++];
                sl->b1b = 1;
                sl->b18 = 0x7f;
                sl->b19 = 0x7f;
                sl->b1a = 0xff;
                sl->f0 = sub->crystalX;
                sl->f8 = lbl_803E41DC + sub->crystalY;
                sl->f10 = sub->crystalZ;
                dir[0] = *(f32*)p32 - sl->f0;
                dir[1] = (lbl_803E41E0 + *(f32*)(p32 + 0x10)) - sl->f8;
                dir[2] = *(f32*)(p32 + 0x20) - sl->f10;
                PSVECNormalize(dir, dir);
                pay.x = *(f32*)p32 - sub->crystalX;
                pay.y = (lbl_803E41E0 + *(f32*)(p32 + 0x10)) - sub->crystalY;
                pay.z = *(f32*)(p32 + 0x20) - sub->crystalZ;
                dir[0] = -dir[0];
                dir[1] = -dir[1];
                dir[2] = -dir[2];
                pay.d = i;
                (*gPartfxInterface)->spawnObject(obj, 0x7f4, &pay, 2, -1, dir);
                dir[0] = *(f32*)p32 - ((GameObject*)lbl_803DDB10)->anim.localPosX;
                dir[1] = lbl_803E41E4;
                dir[2] = *(f32*)(p32 + 0x20) - ((GameObject*)lbl_803DDB10)->anim.localPosZ;
                PSVECNormalize(dir, dir);
                pay.x = lbl_803E41E8;
                pay.y = lbl_803E41DC;
                pay.z = lbl_803E41E8;
                pay.d = i + 3;
                (*gPartfxInterface)->spawnObject(lbl_803DDB10, 0x7f4, &pay, 2, -1, dir);
                pay.x = *(f32*)p32;
                pay.y = *(f32*)(p32 + 0x10);
                pay.z = *(f32*)(p32 + 0x20);
                if (sub->chime[3] > 0x14)
                {
                    pay.x = *(f32*)p32;
                    pay.y = *(f32*)(p32 + 0x10);
                    pay.z = *(f32*)(p32 + 0x20);
                    pay.c = i;
                }
                pay.x = *(f32*)p32;
                pay.y = *(f32*)(p32 + 0x10);
                pay.z = *(f32*)(p32 + 0x20);
                pay.c = i;
                sub->beams[idx++].b1b = 1;
                count++;
            }
            p16 += 2;
            p32 += 4;
            i++;
        }
        while (i < 3);
        if (sub->pylonTimer[0] + (sub->pylonTimer[1] + sub->pylonTimer[2]) < 0x12c
            && (int)randomGetRange(0, 3) == 0)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x81, NULL, 0, -1, NULL);
        }
        if (sub->pylonTimer[0] != 0 || sub->pylonTimer[1] != 0 || sub->pylonTimer[2] != 0)
        {
            if (sub->chime[0] > 0x64)
            {
                sub->chime[0] = 0;
            }
            if (sub->chime[1] > 0x64)
            {
                sub->chime[1] = 0;
            }
            if (sub->chime[2] > 0x64)
            {
                sub->chime[2] = 0;
            }
            if (sub->chime[3] > 0x14)
            {
                sub->chime[3] = 0;
            }
            sub->chime[0] += framesThisStep;
            sub->chime[1] += framesThisStep;
            sub->chime[2] += framesThisStep;
            sub->chime[3] += framesThisStep;
        }
        if (count == 3)
        {
            if (sub->charge == 0)
            {
                Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
                getEnvfxAct(0, 0, 0x7f, 0);
            }
            sub->charge += framesThisStep;
        }
        if (sub->charge >= 0x3c)
        {
            f32 fr = (f32)(sub->charge - 0x3c) / lbl_803E41EC;
            CrystalBeam* sl = &sub->beams[idx];
            sl->b1b = 1;
            sl->b18 = 0;
            sl->b19 = 0;
            sl->b1a = 0;
            sl->f0 = ((GameObject*)obj)->anim.localPosX;
            sl->f8 = lbl_803E41F0 + ((GameObject*)obj)->anim.localPosY;
            sl->f10 = ((GameObject*)obj)->anim.localPosZ;
            sl->f4 = sl->f0;
            sl->fc = -(lbl_803E41F4 * fr - sl->f8);
            sl->f14 = sl->f10;
        }
        *(s16*)obj += framesThisStep * (count * 0x7e);
    }
    if (count != 0)
    {
        if (Sfx_IsPlayingFromObjectChannel((int)obj, 0x40) == 0)
        {
            Sfx_PlayFromObject((int)obj, SFXsk_planteater11);
            sub->humVolume = lbl_803E41F8;
        }
        else
        {
            f32 vol = lbl_803E41FC + (f32)count / lbl_803E4200;
            sub->humVolume = (vol - sub->humVolume) * lbl_803E4204 + sub->humVolume;
            if (sub->charge >= 0x3c)
            {
                sub->humVolume = vol;
            }
            Sfx_SetObjectChannelVolume((int)obj, 0x40, 0x64, sub->humVolume);
        }
    }
    i = 0;
    p16 = (char*)sub;
    do
    {
        s16 v = *(s16*)(p16 + 0x30);
        if (v != 0 && v < 0x80)
        {
            *(s16*)(p16 + 0x30) = v + framesThisStep;
            if (v == 1 && *(s16*)(p16 + 0x30) > 1)
            {
                Sfx_PlayFromObject((int)obj, SFXsk_toysq2_c);
            }
            if (v < 0x1e && *(s16*)(p16 + 0x30) >= 0x1e)
            {
                Sfx_PlayFromObject((int)obj, SFXsk_trbark1);
            }
        }
        p16 += 2;
        i++;
    }
    while (i < 3);
    *(s16*)obj += framesThisStep * 0x2a;
}

extern int fn_8019AF64(int* obj, void* path, f32 f, int phase, void* spd);
