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

extern u8 lbl_80329514[];
extern f32 lbl_803E6398;
extern void fn_802960E8(void* playerObj, int p2);
extern f32 timeDelta;
extern int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);

undefined4
FUN_80200558(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)param_9)->extra;
    control = (DbStealerwormControl*)groundState->control;
    control->flags14 |= 2;
    control->flags15 |= 4;
    state->moveSpeed = lbl_803E6F80;
    if (state->moveJustStartedA != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 0x1f;
    if (state->moveJustStartedA != '\0')
    {
        control->linkedObj = (int)state->targetObj;
        control->unk1C = 0x24;
        control->unk2C = 0;
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                            control->linkedObj, 0x11, param_9, 0x12, param_13, param_14, param_15, param_16);
        FUN_80006824(param_9, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)param_9)->anim.currentMoveProgress)
    {
        control->unk34 = 1;
    }
    return 0;
}

undefined4
FUN_80200740(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float fVar1;
    uint uVar2;
    GameObject* targetObj;
    short* psVar4;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;
    double dVar6;
    undefined4 local_48;
    undefined4 local_44;
    undefined4 local_40;
    undefined4 local_3c;
    undefined4 local_38;
    undefined4 local_34;
    undefined4 local_30;
    undefined4 local_2c;
    undefined4 local_28;
    float local_24;
    float local_20;
    float local_1c;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)param_9)->extra;
    control = (DbStealerwormControl*)groundState->control;
    control->flags14 |= 2;
    control->flags15 &= 0xfb;
    fVar1 = lbl_803E6F88;
    state->animSpeedA = state->animSpeedA / lbl_803E6F88;
    state->animSpeedB = state->animSpeedB / fVar1;
    state->moveSpeed = lbl_803E6F8C;
    if (state->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 0x1f;
    targetObj = (GameObject*)state->targetObj;
    if ((((GameObject*)param_9)->anim.currentMoveProgress <= lbl_803E6F84) ||
        (((GameObject*)param_9)->anim.localPosY < targetObj->anim.localPosY - lbl_803E6F90))
    {
        local_24 = targetObj->anim.localPosX - ((GameObject*)param_9)->anim.localPosX;
        local_20 = targetObj->anim.localPosY - (((GameObject*)param_9)->anim.localPosY + lbl_803E6F94);
        local_1c = targetObj->anim.localPosZ - ((GameObject*)param_9)->anim.localPosZ;
        dVar6 = FUN_80293900((double)(local_1c * local_1c + local_24 * local_24 + local_20 * local_20));
        if (dVar6 < (double)lbl_803E6F50)
        {
            local_40 = (undefined4)state->targetObj;
            psVar4 = (short*)control->msgStack;
            local_48 = 0xe;
            local_44 = 1;
            uVar2 = FUN_80006ab8(psVar4);
            if (uVar2 == 0)
            {
                FUN_80006ac4(psVar4, (uint) & local_48);
            }
            control->unk34 = 1;
        }
    }
    else
    {
        psVar4 = (short*)control->msgStack;
        local_30 = 9;
        local_2c = 0;
        local_28 = 0x24;
        uVar2 = FUN_80006ab8(psVar4);
        if (uVar2 == 0)
        {
            FUN_80006ac4(psVar4, (uint) & local_30);
        }
        control->unk34 = 1;
        local_34 = (undefined4)state->targetObj;
        psVar4 = (short*)control->msgStack;
        local_3c = 7;
        local_38 = 1;
        uVar2 = FUN_80006ab8(psVar4);
        if (uVar2 == 0)
        {
            FUN_80006ac4(psVar4, (uint) & local_3c);
        }
        control->unk34 = 1;
    }
    return 0;
}

undefined4
FUN_80201260(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    uint uVar2;
    short* psVar3;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;
    undefined4 local_28;
    undefined4 local_24;
    undefined4 local_20;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)param_9)->extra;
    control = (DbStealerwormControl*)groundState->control;
    if (state->moveJustStartedA != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    if (state->moveJustStartedA != '\0')
    {
        state->targetObj = 0;
        if (control->linkedObj != 0)
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                control->linkedObj, 0x11, param_9, 0x10, param_13, param_14, param_15, param_16);
            control->linkedObj = 0;
        }
        iVar1 = FUN_80017a98();
        iVar1 = (**(code**)(**(int**)(*(int*)(iVar1 + 200) + 0x68) + 0x44))();
        if (iVar1 == 0)
        {
            uVar2 = randomGetRange(0, 2);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + uVar2 * 4));
        }
        else
        {
            uVar2 = randomGetRange(3, 4);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + uVar2 * 4));
        }
        local_20 = control->unk30;
        local_24 = control->unk2C;
        psVar3 = (short*)control->msgStack;
        local_28 = control->unk28;
        uVar2 = FUN_80006ab8(psVar3);
        if (uVar2 == 0)
        {
            FUN_80006ac4(psVar3, (uint) & local_28);
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
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 uVar1;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)param_9)->extra;
    if (state->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar1 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    state->moveSpeed = lbl_803E6F8C;
    if (state->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, uVar1, param_13, param_14, param_15, param_16);
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
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 uVar1;
    BaddieState* state;

    state = (BaddieState*)param_10;
    if (state->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar1 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    state->moveSpeed = lbl_803E6F8C;
    if (state->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, uVar1, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 1;
    return 0;
}

undefined4
FUN_802017a0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    uint uVar1;
    undefined4 uVar2;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)param_9)->extra;
    control = (DbStealerwormControl*)groundState->control;
    if (state->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar2 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (state->moveJustStartedA != '\0')
    {
        uVar1 = randomGetRange(0, 1);
        if (uVar1 == 0)
        {
            if (state->moveJustStartedA != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, uVar2, param_13, param_14, param_15, param_16);
                state->moveDone = 0;
            }
        }
        else if (state->moveJustStartedA != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, uVar2, param_13, param_14, param_15, param_16);
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
FUN_80202004(double param_1, double param_2, undefined8 param_3, double param_4, ushort* param_5,
             int param_6)
{
    int iVar1;
    undefined4 uVar2;
    int iVar3;
    double dVar4;
    double dVar5;
    float local_48[5];

    iVar3 = *(int*)(param_5 + 0x5c);
    iVar1 = Obj_GetYawDeltaToObject(param_5, param_6, local_48);
    if ((double)lbl_803E6F40 == param_4)
    {
        uVar2 = 0;
    }
    else
    {
        dVar5 = (double)(float)((double)(float)((double)local_48[0] - param_1) / param_4);
        dVar4 = dVar5;
        if (dVar5 < (double)lbl_803E6F40)
        {
            dVar4 = -dVar5;
        }
        if ((double)lbl_803E7008 <= dVar4)
        {
            if (dVar5 < (double)lbl_803E6F40)
            {
                param_2 = -param_2;
            }
            *(float*)(iVar3 + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)iVar1 ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(iVar3 + 0x280)) +
                *(float*)(iVar3 + 0x280);
            *(float*)(iVar3 + 0x284) = lbl_803E6F40;
            uVar2 = 0;
        }
        else
        {
            uVar2 = 1;
        }
    }
    return uVar2;
}

int dbstealerworm_stateHandlerA06(int obj, int p2);

undefined4
FUN_80202130(double param_1, double param_2, undefined8 param_3, double param_4, ushort* param_5,
             int param_6)
{
    int iVar1;
    int iVar2;
    double dVar3;
    float local_58[7];

    iVar2 = *(int*)(param_5 + 0x5c);
    if ((param_5 != (ushort*)0x0) && (param_6 != 0))
    {
        iVar1 = Obj_GetYawDeltaToObject(param_5, param_6, local_58);
        if ((double)lbl_803E6F40 != param_4)
        {
            if ((double)local_58[0] < param_1)
            {
                dVar3 = (double)(*(float*)(param_5 + 8) - *(float*)(param_6 + 0x10));
                if (dVar3 < (double)lbl_803E6F40)
                {
                    dVar3 = -dVar3;
                }
                if (dVar3 < (double)lbl_803E7010)
                {
                    return 1;
                }
            }
            *(float*)(iVar2 + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)iVar1 ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(iVar2 + 0x280)) +
                *(float*)(iVar2 + 0x280);
            *(float*)(iVar2 + 0x284) = lbl_803E6F40;
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
    extern int Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern f32 Vec_xzDistance(int, int);
    extern int Sfx_IsPlayingFromObjectChannel(int, int);
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_StopObjectChannel(int, int);
    extern f32 timeDelta;
    extern f32 lbl_803E639C;
    extern f32 lbl_803E63A0;
    extern f32 lbl_803E63A4;
    extern f32 lbl_803E63A8;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    Dll22CState* blob = ((GameObject*)obj)->extra;
    int player;
    int h;
    f32 d;
    f32 k;

    player = Obj_GetPlayerObject();
    if ((u32)player == 0)
    {
        return;
    }
    switch (blob->mode)
    {
    case 0:
        if (GameBit_Get(blob->gameBit) != 0 && blob->unk0C != 1)
        {
            if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E639C)
            {
                if (((GameObject*)obj)->anim.localPosY < lbl_803E63A0 + *(f32*)(data + 0xc))
                {
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                    {
                        Sfx_PlayFromObject(obj, 0x116);
                        blob->sfxLatch = 1;
                    }
                    ((GameObject*)obj)->anim.localPosY += timeDelta;
                    if (((GameObject*)obj)->anim.localPosY >= lbl_803E63A0 + *(f32*)(data + 0xc))
                    {
                        ((GameObject*)obj)->anim.localPosY = lbl_803E63A0 + *(f32*)(data + 0xc);
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
                if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E639C)
                {
                    if (((GameObject*)obj)->anim.localPosY < (k = lbl_803E63A0) + *(f32*)(data + 0xc))
                    {
                        ((GameObject*)obj)->anim.localPosY += timeDelta;
                        if (((GameObject*)obj)->anim.localPosY >= k + *(f32*)(data + 0xc))
                        {
                            ((GameObject*)obj)->anim.localPosY = k + *(f32*)(data + 0xc);
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
            d = Vec_xzDistance(obj + 0x18, player + 0x18);
            if (d < lbl_803E63A4)
            {
                if (((GameObject*)obj)->anim.localPosY == lbl_803E63A0 + *(f32*)(data + 0xc))
                {
                    blob->mode = 3;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                    {
                        Sfx_PlayFromObject(obj, 0x1cb);
                        blob->sfxLatch = 1;
                    }
                }
                else if (((GameObject*)obj)->anim.localPosY == d - lbl_803E63A8)
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
                if (*(f32*)(player + 0x10) < *(f32*)(data + 0xc))
                {
                    blob->mode = 3;
                    if (blob->sfxLatch == 1)
                    {
                        blob->sfxLatch = 0;
                    }
                }
                else if (*(f32*)(player + 0x10) > *(f32*)(data + 0xc))
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
        if (((GameObject*)obj)->anim.localPosY > *(f32*)(data + 0xc) - (k = lbl_803E63A8))
        {
            ((GameObject*)obj)->anim.localPosY -= timeDelta;
            if (((GameObject*)obj)->anim.localPosY <= *(f32*)(data + 0xc) - k)
            {
                ((GameObject*)obj)->anim.localPosY = *(f32*)(data + 0xc) - k;
                blob->mode = 2;
                Sfx_StopObjectChannel(obj, 8);
                blob->pauseTimer = 0x64;
            }
            Vec_xzDistance(obj + 0x18, player + 0x18);
        }
        else
        {
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(obj + 0x18, player + 0x18);
            blob->mode = 2;
            blob->pauseTimer = 0x64;
        }
        break;
    case 4:
        if (((GameObject*)obj)->anim.localPosY < (k = lbl_803E63A0) + *(f32*)(data + 0xc))
        {
            ((GameObject*)obj)->anim.localPosY += timeDelta;
            if (((GameObject*)obj)->anim.localPosY >= k + *(f32*)(data + 0xc))
            {
                ((GameObject*)obj)->anim.localPosY = k + *(f32*)(data + 0xc);
                blob->mode = 2;
                blob->pauseTimer = 0x64;
                Sfx_StopObjectChannel(obj, 8);
            }
            Vec_xzDistance(obj + 0x18, player + 0x18);
        }
        else
        {
            blob->mode = 2;
            blob->pauseTimer = 0x64;
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(obj + 0x18, player + 0x18);
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
