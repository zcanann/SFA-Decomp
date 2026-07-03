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
 * DR/dll_0149_cfwindlift.c; their prototypes appear here.
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

/* babycloudrunner anim-event sfx dispatcher: walk the current move's event
 * list; event 0 plays sfxIds[0], event 7 plays sfxIds[1], event 9 plays a
 * fixed whine; if any of the "turn" events (1..4) fired, play sfxIds[2]. */
void FUN_8019b1d8(u32 unused1, u32 unused2, u16* sfxIds)
{
    u32 obj;
    int latchedCmd;
    int cmdIndex;
    u64 context;

    context = FUN_80286840();
    obj = (u32)((u64)context >> 0x20);
    latchedCmd = 0;
    for (cmdIndex = 0; cmdIndex < *(char*)((int)context + 0x1b); cmdIndex = cmdIndex + 1)
    {
        switch (*(u8*)((int)context + cmdIndex + 0x13))
        {
        case 0:
            if (sfxIds != 0x0)
            {
                FUN_80006824(obj, *sfxIds);
            }
            break;
        case 1:
            latchedCmd = 1;
            break;
        case 2:
            latchedCmd = 2;
            break;
        case 3:
            latchedCmd = 3;
            break;
        case 4:
            latchedCmd = 4;
            break;
        case 7:
            if (sfxIds != 0x0)
            {
                FUN_80006824(obj, sfxIds[1]);
            }
            break;
        case 9:
            FUN_80006824(obj, SFXsk_trwhin3);
        }
    }
    if ((latchedCmd != 0) && (sfxIds != 0x0))
    {
        FUN_80006824(obj, sfxIds[2]);
    }
    FUN_8028688c();
    return;
}

/* babycloudrunner fly-toward-target: aim the flier at 'target'. Computes the
 * distance to target; if closer than a dt-scaled threshold returns 1 (arrived),
 * else sets the velocity vector (self+0x12/0x14/0x16) toward the target, turns
 * the heading (self+0) toward it by a dt-scaled yaw step, kicks the fly move
 * 0x1a, and returns 0 (still travelling). */
u32
FUN_8019b2e0(double dt, short* self, short* target, float* param_4, u32 param_5,
             u32 param_6, u32 param_7, u32 param_8, u32 param_9)
{
    int newYaw;
    short yawDelta;
    u32 result;
    double dirY;
    double dirZ;
    double dirX;
    u64 fpSlot5;
    u64 fpSlot6;
    u64 fpSlot7;
    u64 fpSlot8;
    float deltaZ;
    float deltaY;
    float deltaX[2];
    u32 cvtSelfHi;
    u32 cvtSelfLo;
    u32 cvtDeltaHi;
    u32 cvtDeltaLo;
    s64 yawWide;

    if (target == 0x0)
    {
        result = 0;
    }
    else
    {
        deltaX[0] = *(float*)(target + 6) - *(float*)(self + 6);
        dirX = (double)deltaX[0];
        deltaY = *(float*)(target + 8) - *(float*)(self + 8);
        deltaZ = *(float*)(target + 10) - *(float*)(self + 10);
        dirY = FUN_80293900((double)(deltaZ * deltaZ + (float)(dirX * dirX) + deltaY * deltaY
        ));
        if ((double)(float)((double)lbl_803E4DBC * dt) <= dirY)
        {
            FUN_8006f7a0(deltaX, &deltaY, &deltaZ);
            *(float*)(self + 0x12) = lbl_803DC074 * (float)((double)deltaX[0] * dt);
            *(float*)(self + 0x14) = lbl_803DC074 * (float)((double)deltaY * dt);
            *(float*)(self + 0x16) = lbl_803DC074 * (float)((double)deltaZ * dt);
            yawDelta = (*target + -0x8000) - *self;
            if (0x8000 < yawDelta)
            {
                yawDelta = yawDelta + 1;
            }
            if (yawDelta < -0x8000)
            {
                yawDelta = yawDelta + -1;
            }
            cvtSelfLo = (int)*self ^ 0x80000000;
            cvtSelfHi = 0x43300000;
            cvtDeltaLo = yawDelta ^ 0x80000000;
            cvtDeltaHi = 0x43300000;
            newYaw = (int)
            ((f32)(s32)
            cvtSelfLo +
                (float)((double)((lbl_803E4DC0 +
                    (float)((double)(u32)cvtDeltaLo
                    )) * (float)(dt * (double)lbl_803DC074)) / dirY)
            )
            ;
            yawWide = (s64)newYaw;
            *self = newYaw;
            dirY = (double)*(float*)(self + 0x14);
            dirZ = (double)*(float*)(self + 0x16);
            FUN_80017a88((double)*(float*)(self + 0x12), dirY, dirZ, self);
            if (self[0x50] != 0x1a)
            {
                FUN_800305f8((double)lbl_803E4DA8, dirY, dirZ, dirX, fpSlot5, fpSlot6, fpSlot7, fpSlot8, self, 0x1a, 0
                             , param_5, param_6, param_7, param_8, param_9);
            }
            FUN_8002f6ac(dt, self, param_4);
            result = 0;
        }
        else
        {
            result = 1;
        }
    }
    return result;
}

u32
FUN_8019b650(u64 param_1, double param_2, double param_3, double param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, short* param_9,
             u32 param_10, u32 param_11, float* param_12, int param_13, u32 param_14
             , u32 param_15, u32 param_16)
{
    return 0;
}

/* babycloudrunner move dispatcher: pick the default or alt action table by the
 * state byte at extra+0x2a0 (== 6 -> alt), run the move; on completion, if the
 * anim raised trigger-command 2, spawn a follow-up. */
u32
FUN_8019b658(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, int obj, u32 param_10
             , ObjAnimUpdateState* animUpdate, u32 param_12, u32 param_13, u32 param_14,
             u32 param_15, u32 param_16)
{
    u32 result;
    int moveResult;
    float* state;
    u32* moveTable;
    u32 defaultActionId;
    u32 defaultActionArg;
    u32 altActionId;
    u32 altActionArg;

    state = ((GameObject*)obj)->extra;
    defaultActionId = DAT_802c2a58;
    defaultActionArg = DAT_802c2a5c;
    altActionId = DAT_802c2a60;
    altActionArg = DAT_802c2a64;
    if (((GameObject*)obj)->seqIndex < 0)
    {
        FUN_800e8630(obj);
        result = 0;
    }
    else
    {
        if (*(char*)(state + 0x2a0) == '\x06')
        {
            moveTable = &altActionId;
        }
        else
        {
            moveTable = &defaultActionId;
        }
        moveResult = FUN_8007f924((int)animUpdate);
        if ((moveResult == 0x283) ||
            (moveResult = FUN_801149b8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj
                                  , animUpdate, state, (short)*moveTable, moveTable[1], param_14, param_15,
                                  param_16), moveResult == 0))
        {
            if (animUpdate->triggerCommand == 2)
            {
                moveResult = FUN_80017a98();
                FUN_80294d40(moveResult, 10);
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

/* babycloudrunner message pump: drain the object's message queue and, for the
 * 0x110001/0x110002/0x110003 relay messages, re-forward them to the message's
 * sender when this object is in the matching state (0x54/0x55/0x56) and the
 * anim clock (animUpdate+0x58) has passed 0xaf; then, over the anim event list,
 * fire gamebit 0x4e0 once states 0x54/0x55/0x56 are all set. */
u32
FUN_8019c318(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 obj
             , u32 param_10, ObjAnimUpdateState* animUpdate, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    int hasMsg;
    u32 alive;
    short* state;
    u32 msgSender;
    u32 msgId;
    u32 msgData[4];

    state = ((GameObject*)obj)->extra;
    msgSender = 0;
    while (hasMsg = ObjMsg_Pop(obj, &msgId, msgData, &msgSender), hasMsg != 0)
    {
        if (msgId == 0x110001)
        {
            if ((*state == 0x54) && (0xaf < *(short*)((char*)animUpdate + 0x58)))
            {
                ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, msgData[0],
                                    0x110001, obj, 0, param_13, param_14, param_15, param_16);
            }
        }
        else if ((int)msgId < 0x110001)
        {
            if (msgId == 0xa0005)
            {
                param_1 = FUN_80017698((int)*state, 1);
            }
        }
        else if (msgId == 0x110003)
        {
            if ((*state == 0x56) && (0xaf < *(short*)((char*)animUpdate + 0x58)))
            {
                ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, msgData[0],
                                    0x110003, obj, 0, param_13, param_14, param_15, param_16);
            }
        }
        else if ((((int)msgId < 0x110003) && (*state == 0x55)) &&
            (0xaf < *(short*)((char*)animUpdate + 0x58)))
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, msgData[0],
                                0x110002, obj, 0, param_13, param_14, param_15, param_16);
        }
    }
    for (hasMsg = 0; hasMsg < (int)(u32)animUpdate->eventCount; hasMsg = hasMsg + 1)
    {
        if (((animUpdate->eventIds[hasMsg] == 1) && (alive = FUN_80017690(0x54), alive != 0))
            && ((alive = FUN_80017690(0x55), alive != 0 && (alive = FUN_80017690(0x56), alive != 0))))
        {
            FUN_80017698(0x4e0, 1);
        }
    }
    return 0;
}

/* babycloudrunner ascend/descend controller: toggles between the climb (5) and
 * dive (0xd) moves based on vertical velocity, computes a clamped anim speed
 * from that velocity, and plays the spit sfx once when the dive move passes its
 * progress threshold (spitFlags bit6 latch at extra+0x244). */
u32
FUN_8019d238(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, u32 obj,
             u32 param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    int state;
    double clampedSpeed;

    state = *(int*)&((GameObject*)obj)->extra;
    if ((((GameObject*)obj)->anim.currentMove != 5) && (((GameObject*)obj)->anim.currentMove != 0xd))
    {
        FUN_800305f8((double)((GameObject*)obj)->anim.currentMoveProgress, param_2, param_3, param_4, param_5,
                     param_6, param_7,
                     param_8, obj, 0xd, 0, param_12, param_13, param_14, param_15, param_16);
    }
    if ((((GameObject*)obj)->anim.currentMove == 5) && (lbl_803E4EC4 < ((GameObject*)obj)->anim.velocityY))
    {
        FUN_800305f8((double)((GameObject*)obj)->anim.currentMoveProgress, param_2, param_3, param_4, param_5,
                     param_6, param_7,
                     param_8, obj, 0xd, 0, param_12, param_13, param_14, param_15, param_16);
    }
    if ((((GameObject*)obj)->anim.currentMove == 0xd) && (((GameObject*)obj)->anim.velocityY < lbl_803E4EB0))
    {
        FUN_800305f8((double)((GameObject*)obj)->anim.currentMoveProgress, param_2, param_3, param_4, param_5,
                     param_6, param_7,
                     param_8, obj, 5, 0, param_12, param_13, param_14, param_15, param_16);
    }
    clampedSpeed = (double)((((GameObject*)obj)->anim.velocityY * lbl_803E4EC0 + lbl_803E4EC8) * lbl_803E4ECC);
    if (clampedSpeed < (double)lbl_803E4EB0)
    {
        clampedSpeed = (double)lbl_803E4EB0;
    }
    if ((double)lbl_803E4ECC < clampedSpeed)
    {
        clampedSpeed = (double)lbl_803E4ECC;
    }
    if (((GameObject*)obj)->anim.currentMove == 0xd)
    {
        if (((GameObject*)obj)->anim.currentMoveProgress <= lbl_803E4ECC)
        {
            *(u8*)(state + 0x244) = *(u8*)(state + 0x244) & 0xbf;
        }
        else if ((*(u8*)(state + 0x244) >> 6 & 1) == 0)
        {
            FUN_80006824(obj, SFXand_spitout);
            *(u8*)(state + 0x244) = *(u8*)(state + 0x244) & 0xbf | 0x40;
        }
    }
    FUN_8002fc3c(clampedSpeed, (double)lbl_803DC074);
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

/* babycloudrunner spawn/hatch anim-event handler: sets up the model's tint
 * params (model+0x20..0x28) from the parent's health (otherObj+0x298), submits
 * a texture query, plays the hatch sfx, then (if the placement bit is set)
 * snaps this object's world position onto the matched group-0x3a partner and
 * re-runs its placement. */
void FUN_8019f1dc(void)
{
    u32 obj;
    int otherObj;
    int* objList;
    int objId;
    int model;
    int* objWalker;
    int listIndex;
    double in_f29;
    double savedZ;
    double in_f30;
    double savedY;
    double in_f31;
    double savedX;
    double in_ps29_1;
    double in_ps30_1;
    double in_ps31_1;
    u64 context;
    int objCount;
    u16 texQueryBuf[4];
    float texParam3;
    float texParam2;
    float texParam1;
    float texParam0;
    float saveF29;
    float saveF29Ps;
    float saveF30;
    float saveF30Ps;
    float saveF31;
    float saveF31Ps;

    saveF31 = (float)in_f31;
    saveF31Ps = (float)in_ps31_1;
    saveF30 = (float)in_f30;
    saveF30Ps = (float)in_ps30_1;
    saveF29 = (float)in_f29;
    saveF29Ps = (float)in_ps29_1;
    context = FUN_8028683c();
    obj = (u32)(context >> 0x20);
    model = *(int*)&((GameObject*)obj)->extra;
    otherObj = FUN_80017a98();
    otherObj = *(int*)(otherObj + 0xb8);
    *(float*)(model + 0x20) = lbl_803E4F58;
    if ((context & 0xff) == 0)
    {
        *(float*)(model + 0x24) = lbl_803E4F6C;
        *(float*)(model + 0x28) = lbl_803E4F70;
    }
    else
    {
        *(float*)(model + 0x24) = lbl_803E4F60 * *(float*)(otherObj + 0x298) + lbl_803E4F5C;
        *(float*)(model + 0x28) = lbl_803E4F68 * *(float*)(otherObj + 0x298) + lbl_803E4F64;
    }
    texParam2 = lbl_803E4F58;
    texParam1 = lbl_803E4F58;
    texParam0 = lbl_803E4F58;
    texParam3 = lbl_803E4F74;
    texQueryBuf[2] = 0;
    texQueryBuf[1] = 0;
    texQueryBuf[0] = *(u16*)(model + 0x50);
    FUN_80017748(texQueryBuf, (float*)(model + 0x20));
    *(u8*)(model + 0x49) = *(u8*)(model + 0x49) | 1;
    FUN_80006824(obj, SFXsk_baptr6_c);
    *(u8*)(model + 0x49) = *(u8*)(model + 0x49) | 2;
    if ((*(u8*)(model + 0x48) >> 6 & 1) != 0)
    {
        model = (int)((GameObject*)obj)->anim.placementData;
        otherObj = 0;
        if (*(short*)(model + 0x1a) == 0)
        {
            otherObj = ObjGroup_FindNearestObject(0x3a, obj, (float*)0x0);
        }
        else
        {
            objList = ObjGroup_GetObjects(0x3a, &objCount);
            objWalker = objList;
            for (listIndex = 0; listIndex < objCount; listIndex = listIndex + 1)
            {
                objId = FUN_8020a468(*objWalker);
                if (*(short*)(model + 0x1a) == objId)
                {
                    otherObj = objList[listIndex];
                    break;
                }
                objWalker = objWalker + 1;
            }
        }
        if (otherObj != 0)
        {
            savedX = (double)((GameObject*)obj)->anim.localPosX;
            savedY = (double)((GameObject*)obj)->anim.localPosY;
            savedZ = (double)((GameObject*)obj)->anim.localPosZ;
            *(u32*)(obj + 0xc) = *(u32*)(otherObj + 0xc);
            *(u32*)(obj + 0x10) = *(u32*)(otherObj + 0x10);
            *(u32*)(obj + 0x14) = *(u32*)(otherObj + 0x14);
            FUN_800e8630(obj);
            ((GameObject*)obj)->anim.localPosX = (float)savedX;
            ((GameObject*)obj)->anim.localPosY = (float)savedY;
            ((GameObject*)obj)->anim.localPosZ = (float)savedZ;
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
    Obj_TransformLocalVectorByWorldMatrix(obj, lbl_80322C38, vec);
    voxmaps_traceScaledVectorEnd(vec2, obj + 3, vec, lbl_803DBE5C);
    PSVECScale(lbl_80322C38, vec2, PSVECDistance((char*)obj + 0xc, vec2));
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
