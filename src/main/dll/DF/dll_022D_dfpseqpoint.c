/* DLL 0x22D - DFPSeqPoint [801FE118-801FEB30) */
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
#include "main/gamebits.h"
#include "main/main.h"

extern void objRenderFn_8003b8f4(f32);

/* dll_224_init: init extra-data fields from other; set obj->0xaf bit 3. */

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/anim.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"

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

typedef struct DfpseqpointPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    u8 pad1A[0x1E - 0x1A];
    s8 unk1E;
    u8 pad1F[0x24 - 0x1F];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DfpseqpointPlacement;

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

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

extern f32 lbl_803E63B8;
extern int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t);
extern void unlockLevel(int a, int b, int c);

undefined4
FUN_80200558(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int control;

    control = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    *(byte*)(control + 0x15) = *(byte*)(control + 0x15) | 4;
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F80;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        ((BaddieState*)param_10)->moveDone = 0;
    }
    ((BaddieState*)param_10)->unk34D = 0x1f;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        *(undefined4*)(control + 0x18) = *(undefined4*)(param_10 + 0x2d0);
        *(undefined2*)(control + 0x1c) = 0x24;
        *(undefined4*)(control + 0x2c) = 0;
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                            *(int*)(control + 0x18), 0x11, param_9, 0x12, param_13, param_14, param_15, param_16);
        FUN_80006824(param_9, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)param_9)->anim.currentMoveProgress)
    {
        *(undefined*)(control + 0x34) = 1;
    }
    return 0;
}

undefined4
FUN_80200740(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float divisor;
    uint queueFull;
    int target;
    short* msgQueue;
    int control;
    double dist;
    undefined4 msgA_id;
    undefined4 msgA_arg1;
    undefined4 msgA_arg2;
    undefined4 msgC_id;
    undefined4 msgC_arg1;
    undefined4 msgC_arg2;
    undefined4 msgB1_id;
    undefined4 msgB1_arg1;
    undefined4 msgB1_arg2;
    float dx;
    float dy;
    float dz;

    control = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    *(byte*)(control + 0x15) = *(byte*)(control + 0x15) & 0xfb;
    divisor = lbl_803E6F88;
    ((BaddieState*)param_10)->animSpeedA = ((BaddieState*)param_10)->animSpeedA / lbl_803E6F88;
    ((BaddieState*)param_10)->animSpeedB = ((BaddieState*)param_10)->animSpeedB / divisor;
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        ((BaddieState*)param_10)->moveDone = 0;
    }
    ((BaddieState*)param_10)->unk34D = 0x1f;
    if ((((GameObject*)param_9)->anim.currentMoveProgress <= lbl_803E6F84) ||
        (((GameObject*)param_9)->anim.localPosY < *(float*)(*(int*)(param_10 + 0x2d0) + 0x10) - lbl_803E6F90))
    {
        target = *(int*)(param_10 + 0x2d0);
        dx = *(float*)(target + 0xc) - ((GameObject*)param_9)->anim.localPosX;
        dy = *(float*)(target + 0x10) - (((GameObject*)param_9)->anim.localPosY + lbl_803E6F94);
        dz = *(float*)(target + 0x14) - ((GameObject*)param_9)->anim.localPosZ;
        dist = FUN_80293900((double)(dz * dz + dx * dx + dy * dy));
        if (dist < (double)lbl_803E6F50)
        {
            msgA_arg2 = *(undefined4*)(param_10 + 0x2d0);
            msgQueue = *(short**)(control + 0x24);
            msgA_id = 0xe;
            msgA_arg1 = 1;
            queueFull = FUN_80006ab8(msgQueue);
            if (queueFull == 0)
            {
                FUN_80006ac4(msgQueue, (uint) & msgA_id);
            }
            *(undefined*)(control + 0x34) = 1;
        }
    }
    else
    {
        msgQueue = *(short**)(control + 0x24);
        msgB1_id = 9;
        msgB1_arg1 = 0;
        msgB1_arg2 = 0x24;
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgB1_id);
        }
        *(undefined*)(control + 0x34) = 1;
        msgC_arg2 = *(undefined4*)(param_10 + 0x2d0);
        msgQueue = *(short**)(control + 0x24);
        msgC_id = 7;
        msgC_arg1 = 1;
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgC_id);
        }
        *(undefined*)(control + 0x34) = 1;
    }
    return 0;
}

undefined4
FUN_80201260(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int useAltSfx;
    uint queueFull;
    short* msgQueue;
    int control;
    undefined4 msg_id;
    undefined4 msg_arg1;
    undefined4 msg_arg2;

    control = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        ((BaddieState*)param_10)->moveDone = 0;
    }
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        *(undefined4*)(param_10 + 0x2d0) = 0;
        if (*(int*)(control + 0x18) != 0)
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                *(int*)(control + 0x18), 0x11, param_9, 0x10, param_13, param_14, param_15, param_16);
            *(undefined4*)(control + 0x18) = 0;
        }
        useAltSfx = FUN_80017a98();
        useAltSfx = (**(code**)(**(int**)(*(int*)(useAltSfx + 200) + 0x68) + 0x44))();
        if (useAltSfx == 0)
        {
            queueFull = randomGetRange(0, 2);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + queueFull * 4));
        }
        else
        {
            queueFull = randomGetRange(3, 4);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + queueFull * 4));
        }
        msg_arg2 = *(undefined4*)(control + 0x30);
        msg_arg1 = *(undefined4*)(control + 0x2c);
        msgQueue = *(short**)(control + 0x24);
        msg_id = *(undefined4*)(control + 0x28);
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msg_id);
        }
        *(undefined4*)(control + 0x3c) = 0;
    }
    ((BaddieState*)param_10)->unk34D = 0x10;
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6FD8;
    ((BaddieState*)param_10)->animSpeedA = lbl_803E6F40;
    if (*(s8*)&((BaddieState*)param_10)->moveDone != '\0')
    {
        *(undefined*)(control + 0x34) = 1;
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
    undefined4 msgArg;
    int control;

    control = *(int*)&((GameObject*)param_9)->extra;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    msgArg = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, msgArg, param_13, param_14, param_15, param_16);
        ((BaddieState*)param_10)->moveDone = 0;
    }
    ((BaddieState*)param_10)->unk34D = 1;
    control = *(int*)(control + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    if ((((BaddieState*)param_10)->eventFlags & 1) != 0)
    {
        ((BaddieState*)param_10)->eventFlags = ((BaddieState*)param_10)->eventFlags & ~1;
        *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 1;
    }
    if (*(s8*)&((BaddieState*)param_10)->moveDone != '\0')
    {
        *(undefined*)(control + 0x34) = 1;
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
    undefined4 msgArg;

    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    msgArg = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, msgArg, param_13, param_14, param_15, param_16);
        ((BaddieState*)param_10)->moveDone = 0;
    }
    ((BaddieState*)param_10)->unk34D = 1;
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
    uint animSel;
    undefined4 msgArg;
    int extra;
    int control;

    extra = *(int*)&((GameObject*)param_9)->extra;
    control = *(int*)(extra + 0x40c);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    msgArg = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        animSel = randomGetRange(0, 1);
        if (animSel == 0)
        {
            if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, msgArg, param_13, param_14, param_15, param_16);
                ((BaddieState*)param_10)->moveDone = 0;
            }
        }
        else if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, msgArg, param_13, param_14, param_15, param_16);
            ((BaddieState*)param_10)->moveDone = 0;
        }
        ((BaddieState*)param_10)->unk34D = 1;
        ((BaddieState*)param_10)->moveSpeed =
            lbl_803E6FDC +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e6f78) /
            lbl_803E6FE0;
    }
    ((BaddieState*)param_10)->animSpeedA = lbl_803E6F40;
    if (*(s8*)&((BaddieState*)param_10)->moveDone != '\0')
    {
        *(undefined*)(control + 0x34) = 1;
    }
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    return 0;
}

undefined4
FUN_80202004(double param_1, double param_2, undefined8 param_3, double param_4, ushort* param_5,
             int param_6)
{
    int yawDelta;
    undefined4 ret;
    int state;
    double absRatio;
    double ratio;
    float yawOut[5];

    state = *(int*)(param_5 + 0x5c);
    yawDelta = Obj_GetYawDeltaToObject(param_5, param_6, yawOut);
    if ((double)lbl_803E6F40 == param_4)
    {
        ret = 0;
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
            *(float*)(state + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(state + 0x280)) +
                *(float*)(state + 0x280);
            *(float*)(state + 0x284) = lbl_803E6F40;
            ret = 0;
        }
        else
        {
            ret = 1;
        }
    }
    return ret;
}

int dbstealerworm_stateHandlerA06(int obj, int p2);

undefined4
FUN_80202130(double param_1, double param_2, undefined8 param_3, double param_4, ushort* param_5,
             int param_6)
{
    int yawDelta;
    int state;
    double heightDiff;
    float yawOut[7];

    state = *(int*)(param_5 + 0x5c);
    if ((param_5 != (ushort*)0x0) && (param_6 != 0))
    {
        yawDelta = Obj_GetYawDeltaToObject(param_5, param_6, yawOut);
        if ((double)lbl_803E6F40 != param_4)
        {
            if ((double)yawOut[0] < param_1)
            {
                heightDiff = (double)(*(float*)(param_5 + 8) - *(float*)(param_6 + 0x10));
                if (heightDiff < (double)lbl_803E6F40)
                {
                    heightDiff = -heightDiff;
                }
                if (heightDiff < (double)lbl_803E7010)
                {
                    return 1;
                }
            }
            *(float*)(state + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(state + 0x280)) +
                *(float*)(state + 0x280);
            *(float*)(state + 0x284) = lbl_803E6F40;
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

void dfpseqpoint_free(void)
{
}

void dfpseqpoint_hitDetect(void)
{
}

void dfpseqpoint_release(void)
{
}

void dfpseqpoint_initialise(void)
{
}

void dfpseqpoint_init(int* obj, u8* init)
{
    DfpSeqPointState* sub;
    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)dfpseqpoint_SeqFn;
    *(s16*)obj = (s16)((s8)init[0x18] << 8);
    sub->triggerRadius = (f32)(s32) * (s16*)(init + 0x1a);
    sub->triggerId = *(s16*)(init + 0x1c);
    sub->triggerMode = init[0x19];
    sub->gameBitGate = *(s16*)(init + 0x1e);
    sub->gameBitDone = *(s16*)(init + 0x20);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    ((DfpFlags7*)&sub->flags0F)->b80 = 0;
}

void DFP_Torch_hitDetect(void);

int dfpseqpoint_getExtraSize(void) { return 0x10; }
int dfpseqpoint_getObjectTypeId(void) { return 0x0; }
int DFP_Torch_getExtraSize(void);

void dfpseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E63B8);
}

void dfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

int dfpseqpoint_SeqFn(int obj, int p2, ObjAnimUpdateState* animUpdate)
{
    extern void unlockLevel(int a, int b, int c);
    extern int mapGetDirIdx(int);
    extern void lockLevel(int, int);
    extern void warpToMap(int, int);
    extern MapEventInterface** gMapEventInterface;
    int blob = *(int*)&((GameObject*)obj)->extra;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int i;

    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (((DfpSeqPointState*)blob)->triggerId)
        {
        case 1:
            switch (animUpdate->eventIds[i])
            {
            case 1:
                if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 1)
                {
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 7, 0);
                }
                else if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 2)
                {
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 7, 0);
                }
                break;
            }
            break;
        case 0xa:
            switch (animUpdate->eventIds[i])
            {
            case 0x14:
                if (*(u32*)&((DfpseqpointPlacement*)data)->unk14 == 0x49de8)
                {
                    ((DfpFlags7*)&((DfpSeqPointState*)blob)->flags0F)->b80 = 1;
                }
                else
                {
                    if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 1 ||
                        (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 2)
                    {
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x32), 0);
                        (*gMapEventInterface)->setMapAct(0x32, 2);
                        warpToMap(0x73, 0);
                    }
                }
                break;
            }
            break;
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

void dfpseqpoint_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern f32 Vec_distance(f32* a, f32* b);
    GameObject* self;
    GameObject* player;
    DfpSeqPointState* state;
    int h;

    self = (GameObject*)obj;
    player = (GameObject*)Obj_GetPlayerObject();
    state = self->extra;
    if (((u32)state->flags0F >> 7 & 1) != 0)
    {
        GameBit_Set(0xef7, 1);
        ((DfpFlags7*)&state->flags0F)->b80 = 0;
    }
    h = state->gameBitDone;
    if (h != -1)
    {
        if (state->doneLatch != 0)
        {
            if (GameBit_Get(h) != 0)
            {
                return;
            }
            GameBit_Set(state->gameBitDone, 1);
            state->doneLatch = 1;
            return;
        }
        if (GameBit_Get(h) != 0)
        {
            state->doneLatch = 1;
            return;
        }
    }
    if (state->doneLatch != 0)
    {
        return;
    }
    switch (state->triggerMode)
    {
    case 0:
        if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) < state->triggerRadius)
        {
            (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                    (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case 1:
        h = state->gameBitGate;
        if (h != -1 && GameBit_Get(h) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                    (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case 2:
        if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) < state->triggerRadius)
        {
            h = state->gameBitGate;
            if (h != -1 && GameBit_Get(h) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                        (void*)obj, -1);
                state->doneLatch = 1;
            }
        }
        break;
    case 3:
        if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) < state->triggerRadius)
        {
            h = state->gameBitGate;
            if (h != -1 && GameBit_Get(h) == 0)
            {
                (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                        (void*)obj, -1);
                GameBit_Set(state->gameBitGate, 1);
                state->doneLatch = 1;
            }
        }
        break;
    case 4:
        h = state->gameBitGate;
        if (h != -1 && GameBit_Get(h) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                    (void*)obj, -1);
            GameBit_Set(state->gameBitGate, 1);
            state->doneLatch = 1;
        }
        break;
    case 5:
        h = state->gameBitGate;
        if (h != -1 && GameBit_Get(h) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                    (void*)obj, -1);
        }
        break;
    }
}

int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
