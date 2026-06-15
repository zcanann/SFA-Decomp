/*
 * DLL 0x157 - spirit door spirit; part of the sandwormBoss 10-DLL
 * container (0x14A CFPowerBase .. 0x157 SpiritDoorSpirit) covering
 * [8019D578-801A0B14).  DLLs 0x148/0x149 are defined in
 * DR/dll_0148_cfguardian.c and DR/dll_0149_cfwindlift.c; their
 * prototypes appear here so MWCC can resolve forward references.
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
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
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

extern f32 lbl_803E422C;
extern uint GameBit_Get(int eventId);
extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern f32 lbl_803E4190;
extern f32 lbl_803E42B8;
extern f32 lbl_803DBE78;
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);

void FUN_8019b1d8(undefined4 param_1, undefined4 param_2, ushort* sfxTable)
{
    uint obj;
    int tailSfxSlot;
    int eventIdx;
    undefined8 retPair;

    retPair = FUN_80286840();
    obj = (uint)((ulonglong)retPair >> 0x20);
    tailSfxSlot = 0;
    for (eventIdx = 0; eventIdx < *(char*)((int)retPair + 0x1b); eventIdx = eventIdx + 1)
    {
        switch (*(u8*)((int)retPair + eventIdx + 0x13))
        {
        case 0:
            if (sfxTable != (ushort*)0x0)
            {
                FUN_80006824(obj, *sfxTable);
            }
            break;
        case 1:
            tailSfxSlot = 1;
            break;
        case 2:
            tailSfxSlot = 2;
            break;
        case 3:
            tailSfxSlot = 3;
            break;
        case 4:
            tailSfxSlot = 4;
            break;
        case 7:
            if (sfxTable != (ushort*)0x0)
            {
                FUN_80006824(obj, sfxTable[1]);
            }
            break;
        case 9:
            FUN_80006824(obj, SFXsk_trwhin3);
        }
    }
    if ((tailSfxSlot != 0) && (sfxTable != (ushort*)0x0))
    {
        FUN_80006824(obj, sfxTable[2]);
    }
    FUN_8028688c();
    return;
}

undefined4
FUN_8019b2e0(double param_1, short* param_2, short* param_3, float* param_4, undefined4 param_5,
             undefined4 param_6, undefined4 param_7, undefined4 param_8, undefined4 param_9)
{
    int newAng;
    short angDelta;
    undefined4 result;
    double dist;
    double velZ;
    double dx;
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
        result = 0;
    }
    else
    {
        local_50[0] = *(float*)(param_3 + 6) - *(float*)(param_2 + 6);
        dx = (double)local_50[0];
        local_54 = *(float*)(param_3 + 8) - *(float*)(param_2 + 8);
        local_58 = *(float*)(param_3 + 10) - *(float*)(param_2 + 10);
        dist = FUN_80293900((double)(local_58 * local_58 + (float)(dx * dx) + local_54 * local_54
        ));
        if ((double)(float)((double)lbl_803E4DBC * param_1) <= dist)
        {
            FUN_8006f7a0(local_50, &local_54, &local_58);
            *(float*)(param_2 + 0x12) = lbl_803DC074 * (float)((double)local_50[0] * param_1);
            *(float*)(param_2 + 0x14) = lbl_803DC074 * (float)((double)local_54 * param_1);
            *(float*)(param_2 + 0x16) = lbl_803DC074 * (float)((double)local_58 * param_1);
            angDelta = (*param_3 + -0x8000) - *param_2;
            if (0x8000 < angDelta)
            {
                angDelta = angDelta + 1;
            }
            if (angDelta < -0x8000)
            {
                angDelta = angDelta + -1;
            }
            uStack_44 = (int)*param_2 ^ 0x80000000;
            local_48 = 0x43300000;
            uStack_3c = (int)angDelta ^ 0x80000000;
            local_40 = 0x43300000;
            newAng = (int)
            ((f32)(s32)
            uStack_44 +
                (float)((double)((lbl_803E4DC0 +
                    (float)((double)CONCAT44(0x43300000, uStack_3c) - DOUBLE_803e4db0
                    )) * (float)(param_1 * (double)lbl_803DC074)) / dist)
            )
            ;
            local_38 = (longlong)newAng;
            *param_2 = (short)newAng;
            dist = (double)*(float*)(param_2 + 0x14);
            velZ = (double)*(float*)(param_2 + 0x16);
            FUN_80017a88((double)*(float*)(param_2 + 0x12), dist, velZ, (int)param_2);
            if (param_2[0x50] != 0x1a)
            {
                FUN_800305f8((double)lbl_803E4DA8, dist, velZ, dx, in_f5, in_f6, in_f7, in_f8, param_2, 0x1a, 0
                             , param_5, param_6, param_7, param_8, param_9);
            }
            FUN_8002f6ac(param_1, (int)param_2, param_4);
            result = 0;
        }
        else
        {
            result = 1;
        }
    }
    return result;
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
             , ObjAnimUpdateState* animUpdate, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 result;
    int hitResult;
    float* state;
    undefined4* coordPair;
    undefined4 coordA0;
    undefined4 coordA1;
    undefined4 coordB0;
    undefined4 coordB1;

    state = ((GameObject*)param_9)->extra;
    coordA0 = DAT_802c2a58;
    coordA1 = DAT_802c2a5c;
    coordB0 = DAT_802c2a60;
    coordB1 = DAT_802c2a64;
    if (((GameObject*)param_9)->seqIndex < 0)
    {
        FUN_800e8630(param_9);
        result = 0;
    }
    else
    {
        if (*(char*)(state + 0x2a0) == '\x06')
        {
            coordPair = &coordB0;
        }
        else
        {
            coordPair = &coordA0;
        }
        hitResult = FUN_8007f924((int)animUpdate);
        if ((hitResult == 0x283) ||
            (hitResult = FUN_801149b8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                  , (int)animUpdate, state, (short)*coordPair, (short)coordPair[1], param_14, param_15,
                                  param_16), hitResult == 0))
        {
            if (animUpdate->triggerCommand == 2)
            {
                hitResult = FUN_80017a98();
                FUN_80294d40(hitResult, 10);
            }
            result = 0;
        }
        else
        {
            result = 1;
        }
    }
    return result;
}

undefined4
FUN_8019c318(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , undefined4 param_10, ObjAnimUpdateState* animUpdate, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int eventIdx;
    uint bitSet;
    short* objType;
    uint popState;
    uint msgId;
    uint msgArgs[4];

    objType = ((GameObject*)param_9)->extra;
    popState = 0;
    while (eventIdx = ObjMsg_Pop(param_9, &msgId, msgArgs, &popState), eventIdx != 0)
    {
        if (msgId == 0x110001)
        {
            if ((*objType == 0x54) && (0xaf < *(short*)((char*)animUpdate + 0x58)))
            {
                ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, msgArgs[0],
                                    0x110001, param_9, 0, param_13, param_14, param_15, param_16);
            }
        }
        else if ((int)msgId < 0x110001)
        {
            if (msgId == 0xa0005)
            {
                param_1 = FUN_80017698((int)*objType, 1);
            }
        }
        else if (msgId == 0x110003)
        {
            if ((*objType == 0x56) && (0xaf < *(short*)((char*)animUpdate + 0x58)))
            {
                ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, msgArgs[0],
                                    0x110003, param_9, 0, param_13, param_14, param_15, param_16);
            }
        }
        else if ((((int)msgId < 0x110003) && (*objType == 0x55)) &&
            (0xaf < *(short*)((char*)animUpdate + 0x58)))
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, msgArgs[0],
                                0x110002, param_9, 0, param_13, param_14, param_15, param_16);
        }
    }
    for (eventIdx = 0; eventIdx < (int)(uint)animUpdate->eventCount; eventIdx = eventIdx + 1)
    {
        if (((animUpdate->eventIds[eventIdx] == 1) && (bitSet = FUN_80017690(0x54), bitSet != 0))
            && ((bitSet = FUN_80017690(0x55), bitSet != 0 && (bitSet = FUN_80017690(0x56), bitSet != 0))))
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
    int state;
    double pitch;

    state = *(int*)&((GameObject*)param_9)->extra;
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
    pitch = (double)((((GameObject*)param_9)->anim.velocityY * lbl_803E4EC0 + lbl_803E4EC8) * lbl_803E4ECC);
    if (pitch < (double)lbl_803E4EB0)
    {
        pitch = (double)lbl_803E4EB0;
    }
    if ((double)lbl_803E4ECC < pitch)
    {
        pitch = (double)lbl_803E4ECC;
    }
    if (((GameObject*)param_9)->anim.currentMove == 0xd)
    {
        if (((GameObject*)param_9)->anim.currentMoveProgress <= lbl_803E4ECC)
        {
            *(byte*)(state + 0x244) = *(byte*)(state + 0x244) & 0xbf;
        }
        else if ((*(byte*)(state + 0x244) >> 6 & 1) == 0)
        {
            FUN_80006824(param_9, SFXand_spitout);
            *(byte*)(state + 0x244) = *(byte*)(state + 0x244) & 0xbf | 0x40;
        }
    }
    FUN_8002fc3c(pitch, (double)lbl_803DC074);
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
    uint obj;
    int other;
    int* objList;
    int objId;
    int self;
    int* objWalk;
    int i;
    double in_f29;
    double savedZ;
    double in_f30;
    double savedY;
    double in_f31;
    double savedX;
    double in_ps29_1;
    double in_ps30_1;
    double in_ps31_1;
    ulonglong retPair;
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
    retPair = FUN_8028683c();
    obj = (uint)(retPair >> 0x20);
    self = *(int*)(obj + 0xb8);
    other = FUN_80017a98();
    other = *(int*)(other + 0xb8);
    *(float*)(self + 0x20) = lbl_803E4F58;
    if ((retPair & 0xff) == 0)
    {
        *(float*)(self + 0x24) = lbl_803E4F6C;
        *(float*)(self + 0x28) = lbl_803E4F70;
    }
    else
    {
        *(float*)(self + 0x24) = lbl_803E4F60 * *(float*)(other + 0x298) + lbl_803E4F5C;
        *(float*)(self + 0x28) = lbl_803E4F68 * *(float*)(other + 0x298) + lbl_803E4F64;
    }
    local_58 = lbl_803E4F58;
    local_54 = lbl_803E4F58;
    local_50 = lbl_803E4F58;
    local_5c = lbl_803E4F74;
    local_64[2] = 0;
    local_64[1] = 0;
    local_64[0] = *(ushort*)(self + 0x50);
    FUN_80017748(local_64, (float*)(self + 0x20));
    *(byte*)(self + 0x49) = *(byte*)(self + 0x49) | 1;
    FUN_80006824(obj, SFXsk_baptr6_c);
    *(byte*)(self + 0x49) = *(byte*)(self + 0x49) | 2;
    if ((*(byte*)(self + 0x48) >> 6 & 1) != 0)
    {
        self = *(int*)(obj + 0x4c);
        other = 0;
        if (*(short*)(self + 0x1a) == 0)
        {
            other = ObjGroup_FindNearestObject(0x3a, obj, (float*)0x0);
        }
        else
        {
            objList = ObjGroup_GetObjects(0x3a, &local_68);
            objWalk = objList;
            for (i = 0; i < local_68; i = i + 1)
            {
                objId = FUN_8020a468(*objWalk);
                if (*(short*)(self + 0x1a) == objId)
                {
                    other = objList[i];
                    break;
                }
                objWalk = objWalk + 1;
            }
        }
        if (other != 0)
        {
            savedX = (double)*(float*)(obj + 0xc);
            savedY = (double)*(float*)(obj + 0x10);
            savedZ = (double)*(float*)(obj + 0x14);
            *(undefined4*)(obj + 0xc) = *(undefined4*)(other + 0xc);
            *(undefined4*)(obj + 0x10) = *(undefined4*)(other + 0x10);
            *(undefined4*)(obj + 0x14) = *(undefined4*)(other + 0x14);
            FUN_800e8630(obj);
            *(float*)(obj + 0xc) = (float)savedX;
            *(float*)(obj + 0x10) = (float)savedY;
            *(float*)(obj + 0x14) = (float)savedZ;
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

/* spiritdoorspirit_getExtraSize == 0x1. */
typedef struct SpiritDoorSpiritState
{
    u8 active; /* gamebit not yet set: render + group 0x4e membership */
} SpiritDoorSpiritState;

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

void spiritdoorspirit_hitDetect(void)
{
}

void spiritdoorspirit_release(void)
{
}

void spiritdoorspirit_initialise(void)
{
}

int cfguardian_getExtraSize(void);
int spiritdoorspirit_getExtraSize(void) { return 0x1; }
int spiritdoorspirit_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
void spiritdoorspirit_free(int x) { ObjGroup_RemoveObject(x, 0x4e); }
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off

void spiritdoorspirit_init(int* obj)
{
    SpiritDoorSpiritState* state = ((GameObject*)obj)->extra;
    state->active = 0;
    *(s8*)&((GameObject*)obj)->anim.alpha = 0;
}

void spiritdoorspirit_update(int* obj)
{
    SpiritDoorSpiritState* sub;
    u8* def;

    sub = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (sub->active == 0)
    {
        sub->active = (u8)(GameBit_Get(((SpiritdoorspiritPlacement*)def)->unk1E) == 0);
        if (sub->active != 0)
        {
            ObjGroup_AddObject(obj, 0x4e);
        }
        if (((GameObject*)obj)->anim.alpha != 0)
        {
            ((GameObject*)obj)->anim.alpha = (u8)(((GameObject*)obj)->anim.alpha - 1);
        }
    }
    else
    {
        fn_80098B18((int)obj, lbl_803DBE78, 5, 0, 0, 0);
        sub->active = (u8)(GameBit_Get(((SpiritdoorspiritPlacement*)def)->unk1E) == 0);
        if (sub->active == 0)
        {
            ObjGroup_RemoveObject(obj, 0x4e);
        }
        if (((GameObject*)obj)->anim.alpha < 0xff)
        {
            ((GameObject*)obj)->anim.alpha = (u8)(((GameObject*)obj)->anim.alpha + 1);
        }
    }
}

int babycloudrunner_setScale(int* obj);

void spiritdoorspirit_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    SpiritDoorSpiritState* state = ((GameObject*)obj)->extra;
    if ((s32)visible != 0)
    {
        if (state->active != 0)
        {
            ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E42B8);
        }
    }
}

void cfprisonguard_hitDetect(int* obj);

#pragma peephole reset
#pragma scheduling reset
