/*
 * DLL 0x149 - CFWindLift (defs CFWindLift + CFTreasWind).
 * TU = 0x8019C784..0x8019D578 (helper fn_8019C784 + windlift_*).
 * Non-owned sibling definitions are collapsed to prototypes in place.
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
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

extern undefined8 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern void objRenderFn_8003b8f4(f32);
extern undefined4 FUN_8006f7a0();
extern int FUN_8007f924();
extern undefined4 FUN_800e8630();
extern int FUN_801149b8();
extern double FUN_80293900();
extern undefined4 FUN_80294d40();

extern undefined4 DAT_802c2a58;
extern undefined4 DAT_802c2a5c;
extern undefined4 DAT_802c2a60;
extern undefined4 DAT_802c2a64;
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
void babycloudrunner_init_OLD_v1_1(int obj);

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


/* Trivial 4b 0-arg blr leaves. */


/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);


extern void* Obj_GetPlayerObject(void);


extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern f32 timeDelta;


void windlift_hitDetect(void)
{
}

void windlift_release(void)
{
}

void windlift_initialise(void)
{
}

void cfpowerbase_free(void);


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


extern u8 framesThisStep;


/* 8b "li r3, N; blr" returners. */
int windlift_getExtraSize(void) { return 0x178; }
int windlift_getObjectTypeId(void) { return 0x0; }
int cfpowerbase_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4190;
#pragma peephole off
void windlift_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4190);
}

void cfpowerbase_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


#pragma peephole reset


/* chained byte bit-extract. */


/* plain forwarder. */

/* Drift-recovery: add new fns with v1.0 names. */
extern f32 lbl_803E416C;
/* ObjLink_DetachChild already declared above as undefined4 ObjLink_DetachChild() */
extern f32 fn_80296214(void* p);
/* ObjMsg_AllocQueue already declared as undefined */
extern void Music_Trigger(int a, int b);

#pragma scheduling off
#pragma peephole off


void windlift_free(int* obj)
{
    void* p = Obj_GetPlayerObject();
    if (p == NULL || fn_80296214(p) == lbl_803E416C)
    {
        Music_Trigger(189, 0);
    }
    ObjGroup_RemoveObject(obj, 73);
}

void cfguardian_free(int* obj, int p2);


#pragma peephole reset
#pragma scheduling reset


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
void windlift_init(int* obj, u8* def)
{
    int i;
    WindLiftSub* sub = ((GameObject*)obj)->extra;
    sub->seqId = ((WindliftObjectDef*)def)->seqId;
    sub->duration = seqStreamLookupFn_8007fff8(lbl_80322A48, 4, sub->seqId);
    sub->gamebit = seqStreamLookupFn_8007fff8(lbl_80322A68, 3, sub->seqId);
    if (sub->gamebit == 0)
    {
        sub->gamebit = -1;
    }
    if (sub->duration == 0)
    {
        sub->duration = 100;
    }
    sub->delay = ((WindliftObjectDef*)def)->delay;
    sub->timer = 0;
    if (*(s8*)(def + 0x19) != 0)
    {
        sub->liftHeight = lbl_803E41C8 * (f32) * (s8*)(def + 0x19);
    }
    else
    {
        sub->liftHeight = lbl_803E41CC;
    }
    ((GameObject*)obj)->anim.rootMotionScale = (*(f32*)(*(char**)&((GameObject*)obj)->anim.modelInstance + 4) * sub->
        liftHeight) / lbl_803E41CC;
    if (GameBit_Get(0x57) != 0 || sub->duration >= 0xa)
    {
        sub->timer = 0x3c;
    }
    sub->active = 1;
    if (sub->gamebit != -1)
    {
        if (GameBit_Get(sub->gamebit) != 0)
        {
            sub->timer = 0x3c;
        }
        else
        {
            sub->active = 0;
            ((GameObject*)obj)->anim.alpha = 0;
        }
    }
    {
        f32 v2 = lbl_803E416C;
        f32 v1 = lbl_803E4168;
        for (i = 0; i < 14; i++)
        {
            sub->slots[i].b10 = 0;
            sub->slots[i].b10 &= ~0xf1;
            sub->slots[i].f4 = v1;
            sub->slots[i].fc = v2;
            sub->slots[i].f8 = v2;
            sub->slots[i].i0 = 0;
            sub->slots[i].b11 = 0;
        }
    }
    ObjGroup_AddObject(obj, 0x49);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E42E0;


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
void fn_8019C784(int* obj, int* rider, WindLiftSlot* slot, f32 pull, int gb, int pm, uint dur, f32 height)
{
    char* player;
    f32 dy;
    f32 dist;
    f32 factor;
    f32 scale;
    u8 flags;
    u8 fl;
    int fe;
    player = (char*)Obj_GetPlayerObject();
    dy = ((GameObject*)rider)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    if (dy < lbl_803E416C)
    {
        return;
    }
    dist = Vec_xzDistance((char*)rider + 0x18, (char*)obj + 0x18);
    if (dist > lbl_803E4170 + height && (slot->b10 & 0xe0) == 0)
    {
        return;
    }
    flags = slot->b10;
    if ((flags & 0x80) != 0 && gb != 0)
    {
        return;
    }
    if (dist < height)
    {
        if ((flags & 0xe0) == 0 || (flags & 0x80) != 0)
        {
            if (gb != 0 && (!flags & 0x80) != 0 && dy < lbl_803E4174)
            {
                slot->b10 |= 0x80;
                return;
            }
            if ((flags & 0x2) != 0)
            {
                if (dy / pull > lbl_803E4178)
                {
                    slot->b10 |= 0x4;
                    slot->b10 &= ~0x8;
                }
                else
                {
                    slot->b10 |= 0x8;
                    slot->b10 &= ~0x4;
                }
                slot->b10 &= ~0x2;
            }
            if (gb == 0)
            {
                slot->b10 |= 0x40;
                slot->b10 &= ~0x20;
                ObjMsg_SendToObject(rider, 0xf, obj, (((slot->b10 & 0xe0) >> 4) << 8) | dur);
                slot->b10 &= ~0x80;
            }
            else
            {
                if (dy > lbl_803E417C)
                {
                    ObjMsg_SendToObject(rider, 0xf, obj, (((slot->b10 & 0xe0) >> 4) << 8) | dur);
                }
                slot->b10 |= 0x20;
                slot->b10 &= ~0x40;
            }
        }
        scale = lbl_803E4180;
        fl = slot->b10;
        fe = fl & 0xe;
        if (fe != 0 && (fl & 8) != 0 && gb == 0)
        {
            pull = pull * lbl_803E4184;
        }
        pull = pull * lbl_803E4184;
        if (pull <= lbl_803E4170)
        {
            return;
        }
        if (dy < lbl_803E4188)
        {
            dy = lbl_803E4188;
        }
        if (gb == 0)
        {
            f32 lim = pull - (pull / lbl_803E418C) * (slot->fc * (slot->fc * slot->fc));
            f32 t;
            if (dy > lim)
            {
                t = lbl_803E416C;
            }
            else
            {
                f32 d = lim - dy;
                if (d > lbl_803E4174)
                {
                    t = lbl_803E4190;
                }
                else
                {
                    t = d / lbl_803E4174;
                }
            }
            factor = t;
            slot->b10 |= 1;
            if (((slot->fc < lbl_803E4194 && slot->b11 % 2 != 0)
                    || (slot->fc > lbl_803E4198 && slot->b11 % 2 == 0))
                && (slot->b10 & 8) != 0)
            {
                if (slot->b11++ > 2)
                {
                    slot->b10 &= ~0x8;
                    slot->b10 |= 0x4;
                }
            }
        }
        else
        {
            f32 v = slot->fc;
            f32 thr;
            if (fe != 0)
            {
                thr = lbl_803E4168;
            }
            else
            {
                thr = lbl_803E419C;
            }
            if (v > thr)
            {
                slot->b11 = 1;
            }
            scale = scale * lbl_803E41A0;
            if (slot->b11 == 0)
            {
                f32 c;
                if ((slot->b10 & 0xe) != 0)
                {
                    c = lbl_803E4190 - dy / (lbl_803E41A4 * pull);
                }
                else
                {
                    c = lbl_803E4190 - dy / (lbl_803E41A8 * pull);
                }
                if (c < lbl_803E416C)
                {
                    c = lbl_803E416C;
                }
                factor = c * c;
            }
            else
            {
                factor = lbl_803E41AC;
            }
        }
        slot->f8 = scale * factor - lbl_803E41B0;
        slot->fc = slot->fc + slot->f8;
        if (slot->fc > lbl_803E41B4)
        {
            slot->fc = lbl_803E41B4;
        }
        if (lbl_803E416C == slot->fc)
        {
            slot->fc = lbl_803E41B8;
        }
        if (dy < lbl_803E4174 && gb != 0)
        {
            slot->fc = lbl_803E416C;
            slot->b11 = 0;
            ObjMsg_SendToObject(rider, 0x10, obj, gb);
            slot->b10 |= 0x80;
            if (pm != 0)
            {
                ((GameObject*)player)->anim.velocityY = lbl_803E416C;
            }
        }
        if (pm != 0)
        {
            fn_80296220(rider, slot->fc);
        }
        else
        {
            ((GameObject*)rider)->anim.localPosY = slot->fc * timeDelta + ((GameObject*)rider)->anim.localPosY;
            ((GameObject*)rider)->anim.velocityY = slot->fc * timeDelta;
        }
    }
    else
    {
        if (pm != 0)
        {
            fn_80296220(rider, lbl_803E416C);
        }
        if (pm == 0)
        {
            ObjMsg_SendToObject(rider, 0x10, obj, gb);
            slot->b10 &= ~0xf1;
            slot->fc = lbl_803E416C;
            slot->b11 = 0;
        }
    }
}
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
void windlift_update(int* obj)
{
    u8* def;
    WindLiftSub* sub = ((GameObject*)obj)->extra;
    int level;
    int gb2;
    char* player;
    f32 pull;
    int idx;
    int j;
    int found;
    int count;
    int** objs;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (sub->active)
    {
        level = (int)(lbl_803E41BC * timeDelta + (f32)(int)((GameObject*)obj)->anim.alpha);
        if (sub->gamebit != -1 && GameBit_Get(sub->gamebit) == 0)
        {
            sub->active = 0;
        }
    }
    else
    {
        level = (int)-(lbl_803E41BC * timeDelta - (f32)(int)((GameObject*)obj)->anim.alpha);
        if (sub->gamebit != -1 && GameBit_Get(sub->gamebit) != 0)
        {
            sub->active = 1;
        }
    }
    ((GameObject*)obj)->anim.alpha = (level < 0) ? 0 : ((level > 0xff) ? 0xff : level);
    if ((GameBit_Get(0x57) != 0 || sub->duration > 0xa) && sub->active)
    {
        int t = sub->timer;
        sub->timer = t + 1;
        if (t < 0x3c && GameBit_Get(sub->seqId) == 0)
        {
            *(s16*)obj -= ((framesThisStep * 100) * (sub->timer * sub->timer)) / 0x3c;
            Obj_SetActiveModelIndex(obj, 0);
            return;
        }
        Obj_SetActiveModelIndex(obj, 1);
        gb2 = GameBit_Get(sub->delay);
        {
            int m = (u16)framesThisStep * 0xb6;
            *(s16*)obj -= m * ((gb2 << 2) + 0xe);
        }
        pull = (f32)((WindliftPlacement*)def)->unk1A;
        player = (char*)Obj_GetPlayerObject();
        if (GameBit_Get(sub->seqId) != 0)
        {
            if (!sub->musicOn)
            {
                sub->musicOn = 1;
                Music_Trigger(0xbd, 1);
            }
            if (player != NULL)
            {
                fn_8019C784(obj, (int*)player, &sub->slots[0], pull, gb2, 1, sub->duration, sub->liftHeight);
            }
        }
        else
        {
            if (sub->musicOn)
            {
                Music_Trigger(0xbd, 0);
                sub->musicOn = 0;
            }
            if ((sub->slots[0].b10 & 0xe0) != 0)
            {
                u8 b;
                fn_80296220((int*)player, lbl_803E416C);
                b = sub->slots[0].b10;
                if ((b & 0xe) != 0)
                {
                    sub->slots[0].b10 = b | 2;
                }
                sub->slots[0].fc = lbl_803E416C;
                sub->slots[0].b11 = 0;
                sub->slots[0].b10 &= ~0xf1;
            }
        }
        objs = (int**)ObjGroup_GetObjects(0x16, &count);
        count = count + 1;
        if (count > 0xe)
        {
            count = 0xe;
        }
        for (j = 1; j < 14; j++)
        {
            sub->slots[j].link14 = -1;
        }
        for (idx = 1; idx < count; idx++)
        {
            found = -1;
            for (j = 1; j < 14; j++)
            {
                if ((u32)sub->slots[j].i0 == (u32) * objs)
                {
                    found = j;
                }
            }
            if (found == -1)
            {
                for (j = 1; j < 0xe; j++)
                {
                    if ((u32)sub->slots[j].i0 == 0)
                    {
                        found = j;
                        sub->slots[j].b10 = 0;
                        sub->slots[j].b10 &= ~0xf1;
                        sub->slots[j].f4 = lbl_803E4168;
                        sub->slots[j].fc = lbl_803E416C;
                        sub->slots[j].f8 = lbl_803E416C;
                        sub->slots[j].i0 = 0;
                        sub->slots[j].b11 = 0;
                        j = 2000;
                    }
                }
                if (found == -1)
                {
                    return;
                }
                sub->slots[found].i0 = (int)*objs;
            }
            sub->slots[found].link14 = found;
            {
                int* rider = *objs;
                if ((((GameObject*)rider)->objectFlags & 0x1000) != 0)
                {
                    objs++;
                }
                else if (rider != NULL)
                {
                    fn_8019C784(obj, *objs++, &sub->slots[found], pull, gb2, 0, sub->duration, sub->liftHeight);
                }
            }
        }
        for (j = 1; j < 14; j++)
        {
            if (sub->slots[j].link14 == -1)
            {
                sub->slots[j].i0 = 0;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int fn_80080150(void* p);

