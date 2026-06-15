/* DLL 0x22C — dll22c objects [801FE118-801FEB30) */
#include "main/game_object.h"
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
#include "main/dll/anim_internal.h"
#include "main/main.h"
#include "main/objlib.h"

extern uint GameBit_Get(int eventId);

extern void objRenderFn_8003b8f4(f32);

/* dll_224_init: init extra-data fields from other; set obj->0xaf bit 3. */

#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/anim.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/resource.h"

/*
 * DbStealerwormControl - the per-family control record hung off
 * GroundBaddieState.control (state+0x40C) for dbstealerworm
 * (extraSize 0x460 = GroundBaddieState 0x410 + a 0x50 private tail;
 * the control record itself is memset(0x50) in dbstealerworm_init).
 */

STATIC_ASSERT(sizeof(DbStealerwormControl) == 0x50);

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

STATIC_ASSERT(sizeof(Dll22CState) == 0x10);

STATIC_ASSERT(offsetof(DbEggState, mode) == 0x118);

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

/* chuka extra block (extraSize 0xC). */
#include "main/dll/baddie/chuka.h"

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

extern undefined4 getLActions();
extern undefined4 FUN_80006824();
extern uint FUN_80006ab8();
extern undefined8 FUN_80006ac4();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined8 FUN_800305f8();
extern undefined4 ObjMsg_SendToObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_8003b818();
extern double FUN_80293900();

extern undefined4 DAT_8032a290;
extern f64 DOUBLE_803e6f78;
extern f64 DOUBLE_803e7000;
extern f32 lbl_803DC074;
extern f32 lbl_803E6F40;
extern f32 lbl_803E6F50;
extern f32 lbl_803E6F60;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6FD8;
extern f32 lbl_803E6FDC;
extern f32 lbl_803E6FE0;
extern f32 lbl_803E6FE4;
extern f32 lbl_803E7008;
extern f32 lbl_803E700C;
extern f32 lbl_803E7010;

extern f32 lbl_803E6398;
extern f32 timeDelta;
extern int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);

undefined4
FUN_80200558(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int statePtr,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;

    state = (BaddieState*)statePtr;
    groundState = ((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)groundState->control;
    control->flags14 |= 2;
    control->flags15 |= 4;
    state->moveSpeed = lbl_803E6F80;
    if (state->moveJustStartedA != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, obj, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 0x1f;
    if (state->moveJustStartedA != '\0')
    {
        control->linkedObj = (int)state->targetObj;
        control->unk1C = 0x24;
        control->unk2C = 0;
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                            control->linkedObj, 0x11, obj, 0x12, param_13, param_14, param_15, param_16);
        FUN_80006824(obj, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)obj)->anim.currentMoveProgress)
    {
        control->unk34 = 1;
    }
    return 0;
}

undefined4
FUN_80200740(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int statePtr,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float slowFactor;
    uint pending;
    GameObject* targetObj;
    short* msgQueue;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;
    double dist;
    undefined4 msgA0;
    undefined4 msgA1;
    undefined4 msgA2;
    undefined4 msgC0;
    undefined4 msgC1;
    undefined4 msgC2;
    undefined4 msgB0;
    undefined4 msgB1;
    undefined4 msgB2;
    float dx;
    float dy;
    float dz;

    state = (BaddieState*)statePtr;
    groundState = ((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)groundState->control;
    control->flags14 |= 2;
    control->flags15 &= 0xfb;
    slowFactor = lbl_803E6F88;
    state->animSpeedA = state->animSpeedA / lbl_803E6F88;
    state->animSpeedB = state->animSpeedB / slowFactor;
    state->moveSpeed = lbl_803E6F8C;
    if (state->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 0x1f;
    targetObj = (GameObject*)state->targetObj;
    if ((((GameObject*)obj)->anim.currentMoveProgress <= lbl_803E6F84) ||
        (((GameObject*)obj)->anim.localPosY < targetObj->anim.localPosY - lbl_803E6F90))
    {
        dx = targetObj->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
        dy = targetObj->anim.localPosY - (((GameObject*)obj)->anim.localPosY + lbl_803E6F94);
        dz = targetObj->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
        dist = FUN_80293900((double)(dz * dz + dx * dx + dy * dy));
        if (dist < (double)lbl_803E6F50)
        {
            msgA2 = (undefined4)state->targetObj;
            msgQueue = (short*)control->msgStack;
            msgA0 = 0xe;
            msgA1 = 1;
            pending = FUN_80006ab8(msgQueue);
            if (pending == 0)
            {
                FUN_80006ac4(msgQueue, (uint) & msgA0);
            }
            control->unk34 = 1;
        }
    }
    else
    {
        msgQueue = (short*)control->msgStack;
        msgB0 = 9;
        msgB1 = 0;
        msgB2 = 0x24;
        pending = FUN_80006ab8(msgQueue);
        if (pending == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgB0);
        }
        control->unk34 = 1;
        msgC2 = (undefined4)state->targetObj;
        msgQueue = (short*)control->msgStack;
        msgC0 = 7;
        msgC1 = 1;
        pending = FUN_80006ab8(msgQueue);
        if (pending == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgC0);
        }
        control->unk34 = 1;
    }
    return 0;
}

undefined4
FUN_80201260(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int statePtr,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int inWater;
    uint rnd;
    short* msgQueue;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;
    undefined4 msg0;
    undefined4 msg1;
    undefined4 msg2;

    state = (BaddieState*)statePtr;
    groundState = ((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)groundState->control;
    if (state->moveJustStartedA != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    if (state->moveJustStartedA != '\0')
    {
        state->targetObj = 0;
        if (control->linkedObj != 0)
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                control->linkedObj, 0x11, obj, 0x10, param_13, param_14, param_15, param_16);
            control->linkedObj = 0;
        }
        inWater = FUN_80017a98();
        inWater = (**(code**)(**(int**)(*(int*)(inWater + 200) + 0x68) + 0x44))();
        if (inWater == 0)
        {
            rnd = randomGetRange(0, 2);
            FUN_80006824(obj, (ushort) * (undefined4*)(&DAT_8032a290 + rnd * 4));
        }
        else
        {
            rnd = randomGetRange(3, 4);
            FUN_80006824(obj, (ushort) * (undefined4*)(&DAT_8032a290 + rnd * 4));
        }
        msg2 = control->unk30;
        msg1 = control->unk2C;
        msgQueue = (short*)control->msgStack;
        msg0 = control->unk28;
        rnd = FUN_80006ab8(msgQueue);
        if (rnd == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msg0);
        }
        control->unk3C = 0;
    }
    state->unk34D = 0x10;
    state->moveSpeed = lbl_803E6FD8;
    state->animSpeedA = lbl_803E6F40;
    if (state->moveDone != '\0')
    {
        control->unk34 = 1;
    }
    return 0;
}

undefined4
FUN_802014c8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int statePtr,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 flagsArg;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;

    state = (BaddieState*)statePtr;
    groundState = ((GameObject*)obj)->extra;
    if (state->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    flagsArg = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    state->moveSpeed = lbl_803E6F8C;
    if (state->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 10, 0, flagsArg, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 1;
    control = (DbStealerwormControl*)groundState->control;
    control->flags14 |= 2;
    if ((state->eventFlags & 1) != 0)
    {
        state->eventFlags &= ~1;
        control->flags14 |= 1;
    }
    if (state->moveDone != '\0')
    {
        control->unk34 = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA09(int obj, int p);

undefined4
FUN_80201658(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int statePtr,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 flagsArg;
    BaddieState* state;

    state = (BaddieState*)statePtr;
    if (state->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    flagsArg = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    state->moveSpeed = lbl_803E6F8C;
    if (state->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 5, 0, flagsArg, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 1;
    return 0;
}

undefined4
FUN_802017a0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int statePtr,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    uint rnd;
    undefined4 flagsArg;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;

    state = (BaddieState*)statePtr;
    groundState = ((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)groundState->control;
    if (state->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    flagsArg = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    if (state->moveJustStartedA != '\0')
    {
        rnd = randomGetRange(0, 1);
        if (rnd == 0)
        {
            if (state->moveJustStartedA != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             obj, 7, 0, flagsArg, param_13, param_14, param_15, param_16);
                state->moveDone = 0;
            }
        }
        else if (state->moveJustStartedA != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 6, 0, flagsArg, param_13, param_14, param_15, param_16);
            state->moveDone = 0;
        }
        state->unk34D = 1;
        state->moveSpeed =
            lbl_803E6FDC +
            (float)((double)CONCAT44(0x43300000, (uint)groundState->aggression) - DOUBLE_803e6f78) / lbl_803E6FE0;
    }
    state->animSpeedA = lbl_803E6F40;
    if (state->moveDone != '\0')
    {
        control->unk34 = 1;
    }
    control->flags14 |= 2;
    return 0;
}

undefined4
FUN_80202004(double param_1, double param_2, undefined8 param_3, double param_4, ushort* obj,
             int target)
{
    int yawDelta;
    undefined4 result;
    int sub;
    double absRatio;
    double ratio;
    float yawOut[5];

    sub = *(int*)(obj + 0x5c);
    yawDelta = Obj_GetYawDeltaToObject(obj, target, yawOut);
    if ((double)lbl_803E6F40 == param_4)
    {
        result = 0;
    }
    else
    {
        ratio = (double)(float)((double)(float)((double)yawOut[0] - param_1) / param_4);
        absRatio = ratio;
        if (ratio < (double)lbl_803E6F40)
        {
            absRatio = -ratio;
        }
        if ((double)lbl_803E7008 <= absRatio)
        {
            if (ratio < (double)lbl_803E6F40)
            {
                param_2 = -param_2;
            }
            *(float*)(sub + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(sub + 0x280)) +
                *(float*)(sub + 0x280);
            *(float*)(sub + 0x284) = lbl_803E6F40;
            result = 0;
        }
        else
        {
            result = 1;
        }
    }
    return result;
}

int dbstealerworm_stateHandlerA06(int obj, int p2);

undefined4
FUN_80202130(double param_1, double param_2, undefined8 param_3, double param_4, ushort* obj,
             int target)
{
    int yawDelta;
    int sub;
    double heightDiff;
    float yawOut[7];

    sub = *(int*)(obj + 0x5c);
    if ((obj != (ushort*)0x0) && (target != 0))
    {
        yawDelta = Obj_GetYawDeltaToObject(obj, target, yawOut);
        if ((double)lbl_803E6F40 != param_4)
        {
            if ((double)yawOut[0] < param_1)
            {
                heightDiff = (double)(*(float*)(obj + 8) - *(float*)(target + 0x10));
                if (heightDiff < (double)lbl_803E6F40)
                {
                    heightDiff = -heightDiff;
                }
                if (heightDiff < (double)lbl_803E7010)
                {
                    return 1;
                }
            }
            *(float*)(sub + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(sub + 0x280)) +
                *(float*)(sub + 0x280);
            *(float*)(sub + 0x284) = lbl_803E6F40;
        }
    }
    return 0;
}

int dbstealerworm_stateHandlerA05(int obj, int p);

void FUN_80204320(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

void fn_80204320(int obj);

void dll_22C_init(int obj, char* p)
{
    extern f32 lbl_803E63A8;
    int b8;

    b8 = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)dll_22C_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(*(char*)(p + 0x18) << 8);
    ((Dll22CState*)b8)->mode = 0;
    ((Dll22CState*)b8)->gameBit = *(s16*)(p + 0x20);
    ((Dll22CState*)b8)->gameBit2 = *(s16*)(p + 0x1e);
    ((Dll22CState*)b8)->raiseHeight = (f32) * (s16*)(p + 0x1a);
    ((Dll22CState*)b8)->unk0C = (u8) * (s16*)(p + 0x1c);
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E63A8;
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
}

void dbegg_release(void);

void dll_22C_hitDetect_nop(void)
{
}

void dll_22C_release_nop(void)
{
}

void dll_22C_initialise_nop(void)
{
}

void doorswitch_render(void);

int dll_22C_SeqFn(void) { return 0x0; }
int dll_22C_getExtraSize_ret_16(void) { return 0x10; }
int dll_22C_getObjectTypeId(void) { return 0x0; }
int doorswitch_getExtraSize(void);

void dll_22C_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E6398);
}

void dfpseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void fn_80204B6C(int p1)
{
    (*gExpgfxInterface)->freeSource2((u32)p1);
    getLActions(p1, p1, 0, 0, 0, 0);
}

void fn_80204BF8(int obj)
{
    extern GameObject* Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern f32 Vec_xzDistance(f32*, f32*);
    extern int Sfx_IsPlayingFromObjectChannel(int, int);
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_StopObjectChannel(int, int);
    extern f32 timeDelta;
    extern f32 lbl_803E639C;
    extern f32 lbl_803E63A0;
    extern f32 lbl_803E63A4;
    extern f32 lbl_803E63A8;
    GameObject* object = (GameObject*)obj;
    ObjPlacement* placement = object->anim.placement;
    Dll22CState* blob = object->extra;
    GameObject* player;
    int h;
    f32 d;
    f32 k;

    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    switch (blob->mode)
    {
    case 0:
        if (GameBit_Get(blob->gameBit) != 0 && blob->unk0C != 1)
        {
            if (Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX) < lbl_803E639C)
            {
                if (object->anim.localPosY < lbl_803E63A0 + placement->posY)
                {
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                    {
                        Sfx_PlayFromObject(obj, 0x116);
                        blob->sfxLatch = 1;
                    }
                    object->anim.localPosY += timeDelta;
                    if (object->anim.localPosY >= lbl_803E63A0 + placement->posY)
                    {
                        object->anim.localPosY = lbl_803E63A0 + placement->posY;
                        blob->mode = 1;
                        Sfx_StopObjectChannel(obj, 8);
                    }
                }
            }
        }
        else
        {
            if (blob->unk0C == 1)
            {
                if (Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX) < lbl_803E639C)
                {
                    if (object->anim.localPosY < (k = lbl_803E63A0) + placement->posY)
                    {
                        object->anim.localPosY += timeDelta;
                        if (object->anim.localPosY >= k + placement->posY)
                        {
                            object->anim.localPosY = k + placement->posY;
                            blob->mode = 1;
                        }
                    }
                }
            }
        }
        break;
    case 1:
        blob->mode = 2;
        blob->pauseTimer = 0x64;
        break;
    case 2:
        h = blob->pauseTimer;
        if (h != 0)
        {
            blob->pauseTimer = h - (int)timeDelta;
            if (blob->pauseTimer <= 0)
            {
                blob->pauseTimer = 0;
            }
        }
        else
        {
            d = Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
            if (d < lbl_803E63A4)
            {
                if (object->anim.localPosY == lbl_803E63A0 + placement->posY)
                {
                    blob->mode = 3;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                    {
                        Sfx_PlayFromObject(obj, 0x1cb);
                        blob->sfxLatch = 1;
                    }
                }
                else if (object->anim.localPosY == d - lbl_803E63A8)
                {
                    blob->mode = 4;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                    {
                        Sfx_PlayFromObject(obj, 0x1cb);
                        blob->sfxLatch = 1;
                    }
                }
            }
            else
            {
                if (player->anim.localPosY < placement->posY)
                {
                    blob->mode = 3;
                    if (blob->sfxLatch == 1)
                    {
                        blob->sfxLatch = 0;
                    }
                }
                else if (player->anim.localPosY > placement->posY)
                {
                    blob->mode = 4;
                    if (blob->sfxLatch == 1)
                    {
                        blob->sfxLatch = 0;
                    }
                }
            }
        }
        break;
    case 3:
        if (object->anim.localPosY > placement->posY - (k = lbl_803E63A8))
        {
            object->anim.localPosY -= timeDelta;
            if (object->anim.localPosY <= placement->posY - k)
            {
                object->anim.localPosY = placement->posY - k;
                blob->mode = 2;
                Sfx_StopObjectChannel(obj, 8);
                blob->pauseTimer = 0x64;
            }
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
        }
        else
        {
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
            blob->mode = 2;
            blob->pauseTimer = 0x64;
        }
        break;
    case 4:
        if (object->anim.localPosY < (k = lbl_803E63A0) + placement->posY)
        {
            object->anim.localPosY += timeDelta;
            if (object->anim.localPosY >= k + placement->posY)
            {
                object->anim.localPosY = k + placement->posY;
                blob->mode = 2;
                blob->pauseTimer = 0x64;
                Sfx_StopObjectChannel(obj, 8);
            }
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
        }
        else
        {
            blob->mode = 2;
            blob->pauseTimer = 0x64;
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
        }
        break;
    }
}

int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
