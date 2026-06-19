/*
 * DLL 0x150 - GCRobotLight (retail object name "GCRobotLigh[t]"), the
 * electric scanning-beam of CloudRunner Fortress. It is spawned as the
 * child of a GCRobotPatrol robot (the patrolling enemy run by
 * dll_00C9_enemy.c, placed in CloudRunner Fortress / fortress.romlist):
 * gcrobotlightbea_update aims a point light along a traced vector (the
 * beam) and gcrobotlightbea_hitDetect flags "player caught in the beam"
 * (hitFlags 0x80) unless playerIsDisguised - the sharp-claw disguise
 * fools it; the parent robot reads this child's hit result to react.
 * "GC" = GameCube: Rare's prefix for content reworked/added when the N64
 * "Dinosaur Planet" became the GameCube Star Fox Adventures (the GCRobot
 * family + GCbaddieShip, the GCrubble/GCpillar destructibles, and the
 * reworked GCRF_* CloudRunner Fortress sequences all carry it).
 *
 * This file is part of the sandwormBoss 10-DLL container (0x14A
 * CFPowerBase .. 0x157 SpiritDoorSpirit) covering [8019D578-801A0B14).
 * DLLs 0x148/0x149 are defined in DR/dll_0148_cfguardian.c and
 * DR/dll_0149_cfwindlift.c; their prototypes appear here so MWCC can
 * resolve forward references.
 */
#include "main/dll/cfguardian_state.h"
#include "main/dll/bit80_struct.h"
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/dll/gcrobotlightbeastate_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/modgfx.h"
#include "main/sky_state.h"
extern u64 FUN_80006824();
extern u32 FUN_80017690();
extern u32 FUN_80017698();
extern u32 FUN_80017a88();
extern int FUN_80017a98();
extern u32 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern u32 FUN_800305f8();
extern u32 ObjHits_SetHitVolumeSlot();
extern u32 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);
extern void* ObjGroup_GetObjects();
extern int ObjMsg_Pop();
extern u32 ObjMsg_SendToObject();
extern u32 ObjLink_DetachChild();
extern u32 FUN_8006f7a0();
extern int FUN_8007f924();
extern u32 FUN_800e8630();
extern int FUN_801149b8();
extern int FUN_8020a468();
extern u64 FUN_8028683c();
extern u32 FUN_80286888();
extern double FUN_80293900();
extern u32 FUN_80294d40();
extern u32 DAT_802c2a58;
extern u32 DAT_802c2a5c;
extern u32 DAT_802c2a60;
extern u32 DAT_802c2a64;
extern f64 DOUBLE_803e4db0;
extern f32 lbl_803DC074;
extern f32 lbl_803E4EC0;
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
extern void* Obj_GetPlayerObject(void);
extern void fn_8003ADC4(int obj, char* tgt, char* p3, int a, u8 inv, int b);
extern f32 lbl_803E4298;
extern f32 lbl_803E429C;
extern void objBboxFn_800640cc(f32* p0, f32* p1, int p5, int* out, int* self, int p8, int p9, int slot, f32 f, u8 arg8);
extern void modelLightStruct_freeSlot(int* p);
extern f32 lbl_803E42A0;
extern f32 lbl_803E42A4;
extern f32 lbl_80322C38[];
extern f32 lbl_803DBE58;
extern f32 lbl_803DBE5C;
extern void* modelLightStruct_createPointLight(int unused, u8 red, u8 green, u8 blue, u8 setFlag);
extern void modelLightStruct_setDistanceAttenuation(u8* obj, f32 a, f32 b);
extern void modelLightStruct_setPosition(void* light, f32 x, f32 y, f32 z);
extern void Obj_TransformLocalVectorByWorldMatrix(void* obj, f32* src, f32* dst);
extern void voxmaps_traceScaledVectorEnd(f32* dst, void* posA, f32* dir, f32 factor);
extern f32 PSVECDistance(void* a, void* b);
extern void PSVECScale(void* in, void* out, f32 scale);
extern void modelLightStruct_setDiffuseColor(void* p, int r, int g, int b, int a);

void FUN_8019b1d8(u32 param_1, u32 param_2, u16* param_3)
{
    u32 uVar1;
    int iVar2;
    int iVar3;
    u64 uVar4;

    uVar4 = FUN_80286840();
    uVar1 = (u32)((u64)uVar4 >> 0x20);
    iVar2 = 0;
    for (iVar3 = 0; iVar3 < *(char*)((int)uVar4 + 0x1b); iVar3 = iVar3 + 1)
    {
        switch (*(u8*)((int)uVar4 + iVar3 + 0x13))
        {
        case 0:
            if (param_3 != 0x0)
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
            if (param_3 != 0x0)
            {
                FUN_80006824(uVar1, param_3[1]);
            }
            break;
        case 9:
            FUN_80006824(uVar1, SFXsk_trwhin3);
        }
    }
    if ((iVar2 != 0) && (param_3 != 0x0))
    {
        FUN_80006824(uVar1, param_3[2]);
    }
    FUN_8028688c();
    return;
}

u32
FUN_8019b2e0(double param_1, short* param_2, short* param_3, float* param_4, u32 param_5,
             u32 param_6, u32 param_7, u32 param_8, u32 param_9)
{
    int iVar1;
    short sVar2;
    u32 uVar3;
    double dVar4;
    double dVar5;
    double dVar6;
    u64 in_f5;
    u64 in_f6;
    u64 in_f7;
    u64 in_f8;
    float local_58;
    float local_54;
    float local_50[2];
    u32 local_48;
    u32 uStack_44;
    u32 local_40;
    u32 uStack_3c;
    s64 local_38;

    if (param_3 == 0x0)
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
            uStack_3c = sVar2 ^ 0x80000000;
            local_40 = 0x43300000;
            iVar1 = (int)
            ((f32)(s32)
            uStack_44 +
                (float)((double)((lbl_803E4DC0 +
                    (float)((double)(u32)uStack_3c
                    )) * (float)(param_1 * (double)lbl_803DC074)) / dVar4)
            )
            ;
            local_38 = (s64)iVar1;
            *param_2 = iVar1;
            dVar4 = (double)*(float*)(param_2 + 0x14);
            dVar5 = (double)*(float*)(param_2 + 0x16);
            FUN_80017a88((double)*(float*)(param_2 + 0x12), dVar4, dVar5, param_2);
            if (param_2[0x50] != 0x1a)
            {
                FUN_800305f8((double)lbl_803E4DA8, dVar4, dVar5, dVar6, in_f5, in_f6, in_f7, in_f8, param_2, 0x1a, 0
                             , param_5, param_6, param_7, param_8, param_9);
            }
            FUN_8002f6ac(param_1, param_2, param_4);
            uVar3 = 0;
        }
        else
        {
            uVar3 = 1;
        }
    }
    return uVar3;
}

u32
FUN_8019b650(u64 param_1, double param_2, double param_3, double param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, short* param_9,
             u32 param_10, u32 param_11, float* param_12, int param_13, u32 param_14
             , u32 param_15, u32 param_16)
{
    return 0;
}

u32
FUN_8019b658(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, int param_9, u32 param_10
             , ObjAnimUpdateState* animUpdate, u32 param_12, u32 param_13, u32 param_14,
             u32 param_15, u32 param_16)
{
    u32 uVar1;
    int iVar2;
    float* pfVar3;
    u32* puVar4;
    u32 local_28;
    u32 local_24;
    u32 local_20;
    u32 local_1c;

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
        iVar2 = FUN_8007f924((int)animUpdate);
        if ((iVar2 == 0x283) ||
            (iVar2 = FUN_801149b8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                  , animUpdate, pfVar3, (short)*puVar4, puVar4[1], param_14, param_15,
                                  param_16), iVar2 == 0))
        {
            if (animUpdate->triggerCommand == 2)
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

u32
FUN_8019c318(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
             , u32 param_10, ObjAnimUpdateState* animUpdate, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    int iVar1;
    u32 uVar2;
    short* psVar3;
    u32 local_28;
    u32 local_24;
    u32 local_20[4];

    psVar3 = ((GameObject*)param_9)->extra;
    local_28 = 0;
    while (iVar1 = ObjMsg_Pop(param_9, &local_24, local_20, &local_28), iVar1 != 0)
    {
        if (local_24 == 0x110001)
        {
            if ((*psVar3 == 0x54) && (0xaf < *(short*)((char*)animUpdate + 0x58)))
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
            if ((*psVar3 == 0x56) && (0xaf < *(short*)((char*)animUpdate + 0x58)))
            {
                ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_20[0],
                                    0x110003, param_9, 0, param_13, param_14, param_15, param_16);
            }
        }
        else if ((((int)local_24 < 0x110003) && (*psVar3 == 0x55)) &&
            (0xaf < *(short*)((char*)animUpdate + 0x58)))
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_20[0],
                                0x110002, param_9, 0, param_13, param_14, param_15, param_16);
        }
    }
    for (iVar1 = 0; iVar1 < (int)(u32)animUpdate->eventCount; iVar1 = iVar1 + 1)
    {
        if (((animUpdate->eventIds[iVar1] == 1) && (uVar2 = FUN_80017690(0x54), uVar2 != 0))
            && ((uVar2 = FUN_80017690(0x55), uVar2 != 0 && (uVar2 = FUN_80017690(0x56), uVar2 != 0))))
        {
            FUN_80017698(0x4e0, 1);
        }
    }
    return 0;
}

u32
FUN_8019d238(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, u32 param_9,
             u32 param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
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
    dVar2 = (double)((((GameObject*)param_9)->anim.velocityY * lbl_803E4EC0 + lbl_803E4EC8) * lbl_803E4ECC);
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
            *(u8*)(iVar1 + 0x244) = *(u8*)(iVar1 + 0x244) & 0xbf;
        }
        else if ((*(u8*)(iVar1 + 0x244) >> 6 & 1) == 0)
        {
            FUN_80006824(param_9, SFXand_spitout);
            *(u8*)(iVar1 + 0x244) = *(u8*)(iVar1 + 0x244) & 0xbf | 0x40;
        }
    }
    FUN_8002fc3c(dVar2, (double)lbl_803DC074);
    return 1;
}

void babycloudrunner_init_OLD_v1_1(int obj)
{
    u32* state;

    state = ((GameObject*)obj)->extra;
    *state = 0;
    state[1] = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0x80;
    return;
}

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
    u32 uVar1;
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
    u64 uVar11;
    int local_68;
    u16 local_64[4];
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
    uVar1 = (u32)(uVar11 >> 0x20);
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
    local_64[0] = *(u16*)(iVar5 + 0x50);
    FUN_80017748(local_64, (float*)(iVar5 + 0x20));
    *(u8*)(iVar5 + 0x49) = *(u8*)(iVar5 + 0x49) | 1;
    FUN_80006824(uVar1, SFXsk_baptr6_c);
    *(u8*)(iVar5 + 0x49) = *(u8*)(iVar5 + 0x49) | 2;
    if ((*(u8*)(iVar5 + 0x48) >> 6 & 1) != 0)
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
            *(u32*)(uVar1 + 0xc) = *(u32*)(iVar2 + 0xc);
            *(u32*)(uVar1 + 0x10) = *(u32*)(iVar2 + 0x10);
            *(u32*)(uVar1 + 0x14) = *(u32*)(iVar2 + 0x14);
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

void gcrobotlightbea_render(void)
{
}

void gcrobotlightbea_release(void)
{
}

void gcrobotlightbea_initialise(void)
{
}

/* EN v1.0 0x801A01E8  size: 296b  gcrobotlightbea_hitDetect: clear the hit
 * flag, then re-set it only if the priority hit is the (undisguised) player
 * and lands inside the beacon's bounding box. */
#pragma scheduling off
#pragma peephole off
void gcrobotlightbea_hitDetect(int obj)
{
    float out[22];
    f32 vec[3];
    void* hit;
    GcRobotLightBeaState* sub = ((GameObject*)obj)->extra;
    ((Bit80*)&sub->hitFlags)->top = 0;
    if (((GameObject*)obj)->ownerObj == NULL) return;
    if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) == 0)
    {
        hit = (void*)(*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject;
        if (hit == NULL) return;
    }
    if (hit != Obj_GetPlayerObject()) return;
    if (playerIsDisguised(hit) != 0) return;
    vec[0] = ((ObjHitsPriorityState*)hit)->primaryRadiusSquared;
    vec[1] = lbl_803E4298 + ((ObjHitsPriorityState*)hit)->localPosX;
    vec[2] = ((ObjHitsPriorityState*)hit)->localPosY;
    if (voxmaps_traceWorldLine((void*)((char*)obj + 0xc), vec) == 0) return;
    if (((GameObject*)obj)->unkF4 != 0 ||
        ((int (*)(int, f32*, f32, int, f32*, int, int, int, int, int))objBboxFn_800640cc)(obj + 0xc, vec, lbl_803E429C, 0, out, obj, 4, -1, 0, 0) == 0)
    {
        ((Bit80*)&sub->hitFlags)->top = 1;
    }
}
void cfperch_render(void);

int gcrobotlightbea_getExtraSize(void) { return 0xc; }
int gcrobotlightbea_getObjectTypeId(void) { return 0x0; }
int cfperch_getExtraSize(void);

u32 fn_801A0174(int* obj) { return (((GcRobotLightBeaState*)(int*)((GameObject*)obj)->extra)->hitFlags >> 7) & 1; }

void gcrobotlightbea_init(int* obj)
{
    GcRobotLightBeaState* state = ((GameObject*)obj)->extra;
    state->light = 0;
    state->unk4 = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0x80;
}

void gcrobotlightbea_update(int* obj)
{
    GcRobotLightBeaState* sub;
    f32 vec[3];
    f32 vec2[3];
    u8 r_byte, g_byte, b_byte;

    sub = ((GameObject*)obj)->extra;
    if (sub->light == NULL)
    {
        sub->light = modelLightStruct_createPointLight((int)obj, 0xfa, 0xfa, 0xfa, 1);
        if (sub->light != NULL)
        {
            modelLightStruct_setDistanceAttenuation(sub->light, lbl_803DBE58, lbl_803E42A0 + lbl_803DBE58);
        }
    }
    ObjHits_SetHitVolumeSlot(obj, 0x17, 0, 0);
    vec[0] = lbl_80322C38[0];
    vec[1] = lbl_80322C38[1];
    vec[2] = lbl_80322C38[2];
    Obj_TransformLocalVectorByWorldMatrix(obj, vec, vec);
    voxmaps_traceScaledVectorEnd(vec2, obj + 0xc, vec, lbl_803DBE5C);
    PSVECDistance((char*)obj + 0xc, vec2);
    PSVECScale(lbl_80322C38, vec2, 0);
    getAmbientColor(0, &r_byte, &g_byte, &b_byte);
    if (sub->light != NULL)
    {
        modelLightStruct_setDiffuseColor(sub->light,
                                         (s32)(lbl_803E42A4 * (f32)(u32)r_byte),
                                         (s32)(lbl_803E42A4 * (f32)(u32)g_byte),
                                         (s32)(lbl_803E42A4 * (f32)(u32)b_byte),
                                         0xff);
        modelLightStruct_setPosition(sub->light, vec2[0], vec2[1], vec2[2]);
    }
}

void spiritdoorspirit_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void gcrobotlightbea_free(int* obj)
{
    GcRobotLightBeaState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL)
    {
        modelLightStruct_freeSlot((int*)state);
    }
    if (((GameObject*)obj)->ownerObj != NULL)
    {
        ObjLink_DetachChild(((GameObject*)obj)->ownerObj, obj);
    }
}

void cfguardian_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
