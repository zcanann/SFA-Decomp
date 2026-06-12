/*
 * sandwormBoss.c — 10-DLL container (DLL 0x14A CFPowerBase .. 0x157
 * SpiritDoorSpirit), TU [8019D578-801A0B14). DLLs 0x148 and 0x149 are
 * defined in dll_0148_cfguardian.c and dll_0149_cfwindlift.c; their
 * definitions here are collapsed to forward prototypes.
 */
#include "main/dll/cfguardian_state.h"
#include "main/dll/wormspitbyte_struct.h"
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/dll/babycloudrunnerflags_struct.h"
#include "main/dll/gcrobotlightbeastate_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/rom_curve_interface.h"
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
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern int Obj_GetYawDeltaToObject();
extern undefined4 objAnimFn_80038f38();
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
extern f32 lbl_803E4244;
extern f32 lbl_803E4258;
extern u8 lbl_803DBE28;
extern u8 lbl_803DBE30;
extern void storeZeroToFloatParam(void* p);
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

#pragma scheduling off
#pragma peephole off
void babycloudrunner_init(int* obj, u8* def)
{
    BabyCloudRunnerState* sub;

    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, 4);
    ((GameObject*)obj)->animEventCallback = (void*)babycloudrunner_SeqFn;
    *(s16*)obj = (s16)(def[0x1d] << 8);
    ObjGroup_AddObject(obj, 3);
    sub = ((GameObject*)obj)->extra;
    sub->unkB0 = 0;
    sub->unkB4 = 0;
    sub->unkB8 = 0;
    sub->unkBC = 0;
    sub->turnLatch = 0;
    sub->behaviourState = def[0x1c];
    sub->unkCC = 0;
    storeZeroToFloatParam(sub);
    sub->linkedObj = 0;
    sub->roostYaw = *(s16*)obj;
    sub->flags22C = 0;
    sub->animSpeed = lbl_803E422C;
    sub->runnerState = 0;
    if (GameBit_Get(*(s16*)(def + 0x22)) != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | 0x4000);
        sub->flags22C = (u8)(sub->flags22C & ~1);
        Obj_RemoveFromUpdateList(obj);
        ObjGroup_RemoveObject(obj, 3);
    }
    else
    {
        sub->runnerIndex = *(s16*)(def + 0x22) - 0x2fc;
        if (((GameObject*)obj)->anim.seqId == 0x788)
        {
            sub->runnerIndex = -1;
            sub->curveSpeed = lbl_803E4244;
            sub->mutterSfxTable = &lbl_803DBE30;
        }
        else
        {
            if (sub->runnerIndex < 0 || sub->runnerIndex > 4)
            {
                sub->runnerState = 3;
            }
            sub->curveSpeed = lbl_803E4258;
            sub->mutterSfxTable = &lbl_803DBE28;
            ObjGroup_AddObject(obj, 0x20);
        }
        ((BabyCloudrunnerFlags*)&sub->spitFlags)->resetLatch = 0;
    }
}

#pragma scheduling on
void babycloudrunner_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    s32 isVisible;

    isVisible = visible;
    if (isVisible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E4228);
    }
    return;
}

#pragma peephole on
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
void sandworm_turnTowardTargetAnim(int* a, int* b, u8* c, int d)
{
    int shifted;
    fn_8003ADC4(a, b, (char*)c + 0x3c, 0x28, 0, 3);
    shifted = Obj_GetYawDeltaToObject((int)a, (int)b, 0) >> 3;
    *(s16*)a += shifted;
    if (d == 0) return;
    if ((s16)shifted > -200 && (s16)shifted < 200)
    {
        if (((BabyCloudRunnerState*)c)->turnLatch != 0)
        {
            ((BabyCloudRunnerState*)c)->turnLatch = 0;
            ObjAnim_SetCurrentMove((int)a, 0, lbl_803E4218, 0);
        }
        else
        {
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)a, lbl_803E423C, timeDelta, 0);
        }
    }
    else
    {
        if (((BabyCloudRunnerState*)c)->turnLatch == 0)
        {
            ((BabyCloudRunnerState*)c)->turnLatch = 1;
            ObjAnim_SetCurrentMove((int)a, 9, lbl_803E4218, 0);
        }
        else
        {
            s16 t;
            if ((s16)shifted > 0)
            {
                t = (s16)shifted >> 2;
            }
            else
            {
                t = -(s16)shifted >> 2;
            }
            ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)a, (f32)t / lbl_803E4240, timeDelta, 0);
        }
    }
}
#pragma dont_inline reset

extern f32 Vec_distance(void* a, void* b);
extern f32 s16toFloat(int a, int b);
extern void objAudioFn_800393f8(int obj, void* p, int a, int b, int c, int d);
extern void gameBitIncrement(int bit);
extern void Sfx_PlayFromObject(int obj, int sfxId);

/* EN v1.0 0x8019E6C8  size: 316b  babycloudrunner_func0B: when the player
 * gets within the trigger radius and the runner is in state 3, fire its
 * burst (notify, bump the counter, set the gamebit); otherwise just play
 * the idle audio cue. */
int babycloudrunner_func0B(void* p)
{
    int* obj;
    int flag;
    u8* r;
    BabyCloudRunnerState* sub;
    u8* q;
    void* player;
    obj = (int*)p;
    sub = ((GameObject*)obj)->extra;
    q = *(u8**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    r = *(u8**)&((GameObject*)obj)->anim.placementData;
    flag = 0;
    if (Vec_distance((char*)player + 0x18, (char*)obj + 0x18) < (f32)(s16) * (s16*)(r + 0x1a))
    {
        if (sub->runnerState == 3)
        {
            if ((((GameObject*)obj)->objectFlags & 0x1000) == 0)
            {
                flag = 1;
            }
        }
    }
    if (flag != 0)
    {
        s16toFloat((int)sub, 0x3c);
        ((GameObject*)obj)->unkF4 = 1;
        *(s16*)obj = sub->roostYaw;
        (*gObjectTriggerInterface)->runSequence(4, obj, -1);
        sub->unk00 = lbl_803E4244;
        gameBitIncrement(0x901);
        sub->behaviourState = 0xc;
        GameBit_Set(*(s16*)(q + 0x1e), 1);
        ((GameObject*)obj)->unkF4 = 0;
        return 1;
    }
    objAudioFn_800393f8((int)obj, (char*)sub + 0x6c, 0x296, 0x1000, -1, 1);
    Sfx_PlayFromObject((int)obj, SFXsk_baptr9_c);
    return 0;
}
void windlift_hitDetect(void);

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

#pragma scheduling on
#pragma peephole on
void babycloudrunner_hitDetect(void)
{
}

void babycloudrunner_release(void)
{
}

void babycloudrunner_initialise(void)
{
}

void cfprisonguard_free(void);

extern void objAudioFn_80039270(int obj, void* p, int id);

/* 8b "li r3, N; blr" returners. */
int babycloudrunner_getExtraSize(void) { return 0x248; }
int cfprisonguard_getExtraSize(void);

/* chained byte bit-extract. */

/* plain forwarder. */

/* Drift-recovery: add new fns with v1.0 names. */
/* ObjLink_DetachChild already declared above as undefined4 ObjLink_DetachChild() */
/* ObjMsg_AllocQueue already declared as undefined */

int babycloudrunner_getObjectTypeId(void) { return 0; }

void spiritdoorspirit_init(int* obj);

#pragma scheduling off
#pragma peephole off
int babycloudrunner_setScale(int* obj)
{
    BabyCloudRunnerState* state = ((GameObject*)obj)->extra;
    return !(state->flags22C & 1);
}

void cfperch_init(int* obj);

void babycloudrunner_free(int* obj)
{
    ObjGroup_RemoveObject(obj, 32);
    ObjGroup_RemoveObject(obj, 3);
}

void gcrobotlightbea_init(int* obj);

extern f32 lbl_803E4230;
extern f32 lbl_803E4234;
extern f32 lbl_803DBE4C;

/* EN v1.0 0x8019E3F4  size: 372b  fn_8019E3F4: pick the burrow/surface move
 * from the vertical speed, clamp the playback rate, latch the spit SFX
 * while surfacing fast, and advance the current move. */
#pragma dont_inline on
#pragma opt_common_subs off
int fn_8019E3F4(int* obj)
{
    f32 speed;
    BabyCloudRunnerState* sub = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.currentMove != 5 && ((GameObject*)obj)->anim.currentMove != 0xd)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject*)obj)->anim.currentMoveProgress, 0);
    }
    if (((GameObject*)obj)->anim.currentMove == 5 && ((GameObject*)obj)->anim.velocityY > lbl_803E422C)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject*)obj)->anim.currentMoveProgress, 0);
    }
    if (((GameObject*)obj)->anim.currentMove == 0xd && ((GameObject*)obj)->anim.velocityY < lbl_803E4218)
    {
        ObjAnim_SetCurrentMove((int)obj, 5, ((GameObject*)obj)->anim.currentMoveProgress, 0);
    }
    speed = ((GameObject*)obj)->anim.velocityY * lbl_803DBE4C + lbl_803E4230;
    speed *= lbl_803E4234;
    if (speed < lbl_803E4218)
    {
        speed = lbl_803E4218;
    }
    if (speed > lbl_803E4234)
    {
        speed = lbl_803E4234;
    }
    if (((GameObject*)obj)->anim.currentMove == 0xd)
    {
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E4234)
        {
            if (!((WormSpitByte*)&sub->spitFlags)->spitLatch)
            {
                Sfx_PlayFromObject((int)obj, SFXand_spitout);
                ((WormSpitByte*)&sub->spitFlags)->spitLatch = 1;
            }
        }
        else
        {
            ((WormSpitByte*)&sub->spitFlags)->spitLatch = 0;
        }
    }
    ((int(*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)((int)obj, speed, timeDelta, 0);
    return 1;
}
#pragma opt_common_subs reset
#pragma dont_inline reset

extern int objUpdateOpacity(int sub);

extern void objMove(int obj, f32 x, f32 y, f32 z);

extern void* getTrickyObject(void);
extern f32 lbl_803E4248;

/* EN v1.0 0x8019E81C  size: 920b  babycloudrunner_SeqFn: range-check the
 * runner against the player and its trigger radii, chirp for queued cues,
 * then steer toward the player (or Tricky) per the current behaviour state. */
int babycloudrunner_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    u8* animUpdateBytes = (u8*)animUpdate;
    s8 inRange;
    s8 i;
    int yaw;
    char* player;
    f32 dx;
    f32 dz;
    f32 distSq;
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    BabyCloudRunnerState* sub = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->seqIndex == 4)
    {
        return 0;
    }
    animUpdate->sequenceEventActive = 0;
    player = (char*)Obj_GetPlayerObject();
    dx = ((GameObject*)player)->anim.localPosX - *(f32*)(def + 8);
    dz = ((GameObject*)player)->anim.localPosZ - *(f32*)(def + 0x10);
    distSq = dx * dx + dz * dz;
    if (distSq < (f32)((*(s16*)(def + 0x1a) / 2) * (*(s16*)(def + 0x1a) / 2)))
    {
        inRange = 1;
    }
    else
    {
        inRange = 0;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
    {
        BabyCloudRunnerState* sub2 = ((GameObject*)obj)->extra;
        char* pp = (char*)Obj_GetPlayerObject();
        u8* def2 = *(u8**)&((GameObject*)obj)->anim.placementData;
        int found = 0;
        if (Vec_distance(pp + 0x18, (char*)obj + 0x18) < (f32) * (s16*)(def2 + 0x1a)
            && sub2->runnerState == 3
            && (((GameObject*)obj)->objectFlags & 0x1000) == 0)
        {
            found = 1;
        }
        if (found != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
    }
    if (inRange == 0 && sub->runnerState == 2)
    {
        f32 radius = (f32) * (s16*)(def + 0x18);
        if ((void*)ObjGroup_FindNearestObject(3, obj, &radius) != NULL)
        {
            inRange = 1;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
        }
    }
    sub->behaviourState = 0;
    switch (sub->behaviourState)
    {
    case 10:
    case 11:
        if (sub->linkedObj != NULL)
        {
            sub->scale *= lbl_803E4248;
            *(f32*)((char*)sub->linkedObj + 8) = sub->scale;
        }
        sub->behaviourState = 0xb;
        if (Vec_distance((char*)obj + 0x18, player + 0x18) < (f32) * (s16*)(def + 0x1a)
            && (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
        {
            sub->behaviourState = 7;
            return 4;
        }
        break;
    case 0:
    case 8:
        animUpdate->hitVolumePair &= ~0x2;
        yaw = Obj_GetYawDeltaToObject((int)obj, (int)player, 0);
        fn_8003ADC4(obj, (int*)player, (char*)sub + 0x3c, 0x28, 0, 3);
        *(s16*)obj += (s16)yaw / 8;
        if (inRange != 0)
        {
            animUpdateBytes[0x90] |= 4;
        }
        else
        {
            animUpdateBytes[0x90] = 8;
        }
        break;
    case 5:
        animUpdate->hitVolumePair &= ~0x2;
        yaw = Obj_GetYawDeltaToObject((int)obj, (int)getTrickyObject(), 0);
        fn_8003ADC4(obj, (int*)getTrickyObject(), (char*)sub + 0x3c, 0x28, 0, 3);
        *(s16*)obj += (s16)yaw / 8;
        break;
    }
    return 0;
}

extern void Sfx_StopObjectChannel(int obj, int ch);

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
void babycloudrunner_update(int* obj)
{
    char* player;
    BabyCloudRunnerState* sub;
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    int found;
    u8* def2;
    int* near;
    BabyCloudRunnerState* sub2;
    int inRange;
    RunnerTarget tgt;
    int mode;
    f32 radius;
    sub = ((GameObject*)obj)->extra;
    player = (char*)Obj_GetPlayerObject();
    getTrickyObject();
    if (GameBit_Get(*(s16*)(def + 0x22)) != 0)
    {
        ((GameObject*)obj)->anim.flags |= 0x4000;
        sub->flags22C &= ~1;
        Obj_RemoveFromUpdateList(obj);
        ObjGroup_RemoveObject(obj, 0x20);
        ObjGroup_RemoveObject(obj, 3);
    }
    if (sub->runnerState == 2 && GameBit_Get(0x66) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
        (*gGameUIInterface)->airMeterSetShutdown();
    }
    else if (fn_80080150(sub) != 0)
    {
        sub->flags22C |= 1;
        sub->behaviourState = 0;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            if (*(s16*)(def + 0x22) != -1)
            {
                GameBit_Set(*(s16*)(def + 0x22), 1);
            }
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= 0x4000;
            sub->flags22C &= ~1;
            Obj_RemoveFromUpdateList(obj);
            ObjGroup_RemoveObject(obj, 0x20);
            ObjGroup_RemoveObject(obj, 3);
            ((GameObject*)obj)->anim.flags |= 0x4000;
        }
        else
        {
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - 1;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        if (sub->runnerState == 0)
        {
            mode = 0x19;
            if ((*gRomCurveInterface)->initCurve((char*)sub + 0x124, obj, lbl_803E424C, &mode, 0) == 0)
            {
                sub->runnerState = 1;
                storeZeroToFloatParam((char*)sub + 0x238);
            }
        }
        else
        {
            if (randFn_80080100(500) != 0)
            {
                int r = randomGetRange(0, 3);
                objAudioFn_80039270((int)obj, (char*)sub + 0x6c, (u16)((s16*)sub->mutterSfxTable)[r]);
            }
            objAnimFn_80038f38((int)obj, (char*)sub + 0x6c);
            if (sub->runnerState == 1 || sub->runnerState == 2)
            {
                f32 speed = sub->curveSpeed;
                Obj_UpdateRomCurveFollowVelocity(obj, (char*)sub + 0x124, speed, lbl_803E4238 * speed,
                                                 lbl_803E4250 * speed, 1);
                Obj_SmoothTurnAnglesTowardVelocity(obj, (char*)obj + 0x24, 0x1e, lbl_803E4238, lbl_803E4254);
                objMove((int)obj, *(f32*)((char*)obj + 0x24), *(f32*)((char*)obj + 0x28), *(f32*)((char*)obj + 0x2c));
                if (sub->runnerState == 1)
                {
                    if (sub->runnerIndex != -1 && GameBit_Get(sub->runnerIndex + 0xb2a) != 0)
                    {
                        sub->runnerState = 2;
                        GameBit_Set(0x66, 0);
                        (*gGameUIInterface)->initAirMeter(lbl_80322B28[sub->runnerIndex], 0x5d1);
                        s16toFloat((int)((char*)sub + 0x238), (s16)lbl_80322B28[sub->runnerIndex]);
                    }
                    fn_8019E3F4(obj);
                    return;
                }
                if (sub->runnerState == 2)
                {
                    near = (int*)ObjGroup_FindNearestObject(3, obj, 0);
                    if (near == NULL || Vec_distance((char*)near + 0x18, (char*)sub + 0x18) >= lbl_803DBE38)
                    {
                        if (near != NULL)
                        {
                            fn_8014C66C(near, Obj_GetPlayerObject());
                        }
                    }
                    else
                    {
                        sandworm_turnTowardTargetAnim(obj, near, (u8*)sub, 0);
                        if (Vec_distance((char*)Obj_GetPlayerObject() + 0x18, (char*)near + 0x18) <= lbl_803DBE3C)
                        {
                            fn_8014C66C(near, Obj_GetPlayerObject());
                        }
                        else
                        {
                            fn_8014C66C(near, obj);
                            if (((GameObject*)obj)->anim.currentMove != 0xd)
                            {
                                ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject*)obj)->anim.currentMoveProgress, 0);
                            }
                            ((int (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(
                                (int)obj, lbl_803E422C, timeDelta, 0);
                        }
                    }
                    fn_8019E3F4(obj);
                }
            }
            inRange = Vec_distance((char*)obj + 0x18, player + 0x18) < (f32)(*(s16*)(def + 0x1a) / 2);
            if (sub->runnerState == 2)
            {
                radius = (f32) * (s16*)(def + 0x18);
                if (fn_80080150((char*)sub + 0x238) != 0)
                {
                    if ((*(u16*)((char*)Obj_GetPlayerObject() + 0xb0) & 0x1000) == 0 && timerCountDown(
                        (char*)sub + 0x238) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
                        (*gGameUIInterface)->airMeterSetShutdown();
                        return;
                    }
                    (*gGameUIInterface)->runAirMeter((int)sub->countdownTimer);
                }
                if (inRange == 0 && (void*)ObjGroup_FindNearestObject(3, obj, &radius) != NULL)
                {
                    inRange = 1;
                }
                if (GameBit_Get(sub->runnerIndex + 0xb2e) != 0)
                {
                    sub->runnerState = 3;
                    (*gGameUIInterface)->airMeterSetShutdown();
                    Sfx_PlayFromObject((int)obj, SFXsp_lf_mutter4);
                    storeZeroToFloatParam((char*)sub + 0x238);
                }
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
                sub2 = ((GameObject*)obj)->extra;
                {
                    char* pp = (char*)Obj_GetPlayerObject();
                    def2 = *(u8**)&((GameObject*)obj)->anim.placementData;
                    found = 0;
                    if (Vec_distance(pp + 0x18, (char*)obj + 0x18) < (f32) * (s16*)(def2 + 0x1a)
                        && sub2->runnerState == 3
                        && (((GameObject*)obj)->objectFlags & 0x1000) == 0)
                    {
                        found = 1;
                    }
                }
                if (found != 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
                }
                else
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
                }
            }
            if (sub->runnerState == 3)
            {
                if (!((WormSpitByte*)&sub->spitFlags)->_p0)
                {
                    tgt.x = *(f32*)(def + 8);
                    tgt.y = *(f32*)(def + 0xc);
                    tgt.z = *(f32*)(def + 0x10);
                    tgt.a = sub->roostYaw;
                    tgt.b = 0;
                    tgt.c = 0;
                    ((GameObject*)obj)->anim.rotY = 0;
                    ((GameObject*)obj)->anim.rotZ = 0;
                    if (dll_2E_func0D(obj, &tgt, lbl_803DBE40, -1, &lbl_803DBE44, &lbl_803DBE48) != 0)
                    {
                        ((WormSpitByte*)&sub->spitFlags)->_p0 = 1;
                        GameBit_Set(0x66, 0);
                    }
                    ((int (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803DBE44, timeDelta, 0);
                }
                else
                {
                    if (inRange != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                        sub->unkB0 = 1;
                    }
                    sandworm_turnTowardTargetAnim(obj, (int*)Obj_GetPlayerObject(), (u8*)sub, 1);
                    if (((int (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(
                        (int)obj, sub->animSpeed, timeDelta, 0) != 0)
                    {
                        if (randFn_80080100(2) != 0)
                        {
                            ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E4218, 0);
                        }
                        else
                        {
                            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E4218, 0);
                        }
                    }
                }
            }
        }
    }
}

extern void getEnvfxAct(int a, int b, int c, int d);
