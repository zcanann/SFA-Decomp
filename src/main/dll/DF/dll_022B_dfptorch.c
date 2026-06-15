#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
#include "main/objlib.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

extern void objRenderFn_8003b8f4(f32);

extern f32 sqrtf(f32 x);

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/baddie_state.h"
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

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

extern undefined4 FUN_80006824();
extern uint FUN_80006ab8();
extern undefined8 FUN_80006ac4();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined8 FUN_800305f8();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjMsg_SendToObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_8003b818();
extern double FUN_80293900();

extern undefined4 DAT_8032a290;
extern ModgfxInterface** gModgfxInterface;
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

extern f32 timeDelta;
extern void fn_80202EF0(int obj, int p2);
extern f32 lbl_803E63E4;
extern f32 lbl_803E63E8;
extern f32 lbl_803E63E0;

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
    float dragDiv;
    uint queueFull;
    int target;
    short* msgQueue;
    int control;
    double dist;
    undefined4 msg0;
    undefined4 msg1;
    undefined4 msg2;
    undefined4 msg3;
    undefined4 msg4;
    undefined4 msg5;
    undefined4 msg6;
    undefined4 msg7;
    undefined4 msg8;
    float dx;
    float dy;
    float dz;

    control = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    *(byte*)(control + 0x15) = *(byte*)(control + 0x15) & 0xfb;
    dragDiv = lbl_803E6F88;
    ((BaddieState*)param_10)->animSpeedA = ((BaddieState*)param_10)->animSpeedA / lbl_803E6F88;
    ((BaddieState*)param_10)->animSpeedB = ((BaddieState*)param_10)->animSpeedB / dragDiv;
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
            msg2 = *(undefined4*)(param_10 + 0x2d0);
            msgQueue = *(short**)(control + 0x24);
            msg0 = 0xe;
            msg1 = 1;
            queueFull = FUN_80006ab8(msgQueue);
            if (queueFull == 0)
            {
                FUN_80006ac4(msgQueue, (uint) & msg0);
            }
            *(undefined*)(control + 0x34) = 1;
        }
    }
    else
    {
        msgQueue = *(short**)(control + 0x24);
        msg6 = 9;
        msg7 = 0;
        msg8 = 0x24;
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msg6);
        }
        *(undefined*)(control + 0x34) = 1;
        msg5 = *(undefined4*)(param_10 + 0x2d0);
        msgQueue = *(short**)(control + 0x24);
        msg3 = 7;
        msg4 = 1;
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msg3);
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
    int handler;
    uint queueFull;
    short* msgQueue;
    int control;
    undefined4 msg0;
    undefined4 msg1;
    undefined4 msg2;

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
        handler = FUN_80017a98();
        handler = (**(code**)(**(int**)(*(int*)(handler + 200) + 0x68) + 0x44))();
        if (handler == 0)
        {
            queueFull = randomGetRange(0, 2);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + queueFull * 4));
        }
        else
        {
            queueFull = randomGetRange(3, 4);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + queueFull * 4));
        }
        msg2 = *(undefined4*)(control + 0x30);
        msg1 = *(undefined4*)(control + 0x2c);
        msgQueue = *(short**)(control + 0x24);
        msg0 = *(undefined4*)(control + 0x28);
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msg0);
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
    undefined4 slot;
    int control;

    control = *(int*)&((GameObject*)param_9)->extra;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    slot = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, slot, param_13, param_14, param_15, param_16);
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
    undefined4 slot;

    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    slot = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, slot, param_13, param_14, param_15, param_16);
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
    uint roll;
    undefined4 slot;
    int extra;
    int control;

    extra = *(int*)&((GameObject*)param_9)->extra;
    control = *(int*)(extra + 0x40c);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    slot = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        roll = randomGetRange(0, 1);
        if (roll == 0)
        {
            if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, slot, param_13, param_14, param_15, param_16);
                ((BaddieState*)param_10)->moveDone = 0;
            }
        }
        else if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, slot, param_13, param_14, param_15, param_16);
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
    undefined4 result;
    int state;
    double diffAbs;
    double diff;
    float yawOut[5];

    state = *(int*)(param_5 + 0x5c);
    yawDelta = Obj_GetYawDeltaToObject(param_5, param_6, yawOut);
    if ((double)lbl_803E6F40 == param_4)
    {
        result = 0;
    }
    else
    {
        diff = (double)(float)((double)(float)((double)yawOut[0] - param_1) / param_4);
        diffAbs = diff;
        if (diff < (double)lbl_803E6F40)
        {
            diffAbs = -diff;
        }
        if ((double)lbl_803E7008 <= diffAbs)
        {
            if (diff < (double)lbl_803E6F40)
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

void DFP_Torch_hitDetect(void)
{
}

void DFP_Torch_release(void)
{
}

void DFP_Torch_initialise(void)
{
}

void chuka_render(void);

int DFP_Torch_getExtraSize(void) { return 0x10; }
int DFP_Torch_getObjectTypeId(void) { return 0x1; }
int chuka_SeqFn(void);

void DFP_Torch_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dfpobjcreator_init(int obj, s8* def);

void DFP_Torch_init(int obj, int def)
{
    DfpTorchState* state = ((GameObject*)obj)->extra;
    void* res;
    f32 spawnArg;
    int motionRate;
    *(s16*)obj = (s16)((*(s8*)(def + 0x18) & 0x3f) << 10);
    motionRate = *(s16*)(def + 0x1a);
    if (motionRate > 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)motionRate / lbl_803E63E4;
    }
    else
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63E8;
    }
    state->mode = *(u8*)(def + 0x19);
    state->gameBit = *(s16*)(def + 0x1e);
    spawnArg = lbl_803E63E0;
    if (state->mode == 0)
    {
        state->lit = 1;
        res = Resource_Acquire(0x69, 1);
        if (*(s16*)(def + 0x1c) == 0)
        {
            (*(void (*)(int, int, void*, int, int, int))(*(int*)(*(int*)res + 4)))(obj, 0, &spawnArg, 0x10004, -1, 0);
        }
    }
    state->colorIdx = (u8) * (s16*)(def + 0x1c);
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
}

void fn_80202EF0(int obj, int p2);

void DFP_Torch_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern char*Camera_GetCurrentViewSlot(void);
    extern void voxmaps_worldToGrid(f32*, s16*);
    extern int voxmaps_traceLine(s16*, s16*, void*, int, int);
    extern f32 sqrtf(f32 x);
    extern u32 randomGetRange(int min, int max);
    extern f32 lbl_803E63C8;
    extern f32 lbl_803E63CC;
    extern f32 lbl_803E63D0;
    extern f32 lbl_803E63D4;
    extern f32 lbl_803E63D8;
    extern f32 lbl_803E63DC;
    extern f32 timeDelta;
    DfpTorchState* state = ((GameObject*)obj)->extra;
    char* cam;
    f32 dist;
    f32 scale;
    struct
    {
        u8 pad[12];
        f32 col[3];
    } fx;
    struct
    {
        s32 out[2];
        s16 g2[4];
        s16 g1[4];
        f32 b[3];
        f32 a[3];
        f32 d[3];
    } stk2;

    if (visible == 0)
    {
        state->flickerTimer = 0;
        state->visibleLatch = 0;
    }
    else
    {
        objRenderFn_8003b8f4(lbl_803E63C8);
        if (state->lit != 0)
        {
            state->visibleLatch = 1;
            cam = Camera_GetCurrentViewSlot();
            stk2.d[0] = *(f32*)(cam + 0xc) - ((GameObject*)obj)->anim.localPosX;
            stk2.d[1] = *(f32*)(cam + 0x10) - ((GameObject*)obj)->anim.localPosY;
            stk2.d[2] = *(f32*)(cam + 0x14) - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(stk2.d[2] * stk2.d[2] + (stk2.d[0] * stk2.d[0] + stk2.d[1] * stk2.d[1]));
            if (dist > lbl_803E63CC)
            {
                scale = lbl_803E63C8 / dist;
                stk2.d[0] *= scale;
                stk2.d[1] *= scale;
                stk2.d[2] *= scale;
                stk2.a[0] = lbl_803E63D0 * stk2.d[0];
                stk2.a[1] = lbl_803E63D0 * stk2.d[1];
                stk2.a[2] = lbl_803E63D0 * stk2.d[2];
                stk2.a[0] = stk2.a[0] + ((GameObject*)obj)->anim.localPosX;
                stk2.a[1] = stk2.a[1] + ((GameObject*)obj)->anim.localPosY;
                stk2.a[2] = stk2.a[2] + ((GameObject*)obj)->anim.localPosZ;
                stk2.b[0] = lbl_803E63D4 * stk2.d[0];
                stk2.b[1] = lbl_803E63D4 * stk2.d[1];
                stk2.b[2] = lbl_803E63D4 * stk2.d[2];
                stk2.b[0] = stk2.b[0] + *(f32*)(cam + 0xc);
                stk2.b[1] = stk2.b[1] + *(f32*)(cam + 0x10);
                stk2.b[2] = stk2.b[2] + *(f32*)(cam + 0x14);
                voxmaps_worldToGrid(stk2.a, stk2.g1);
                voxmaps_worldToGrid(stk2.b, stk2.g2);
                if (voxmaps_traceLine(stk2.g1, stk2.g2, stk2.out, 0, 0) == 0)
                {
                    state->visibleLatch = 0;
                    (*gExpgfxInterface)->freeSource((u32)obj);
                }
            }
            if (state->flickerTimer > 0)
            {
                state->flickerTimer -= (s16)timeDelta;
            }
            else
            {
                if (state->visibleLatch != 0)
                {
                    fx.col[0] = lbl_803E63D8;
                    fx.col[1] = lbl_803E63DC;
                    fx.col[2] = lbl_803E63D8;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x1f7, &fx, 0x12, -1,
                                                     NULL);
                }
                state->flickerTimer = (s16)(randomGetRange(-10, 10) + 0x3c);
            }
        }
    }
}

void fn_80204098(int obj);

void DFP_Torch_update(int obj)
{
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_StopObjectChannel(int, int);
    extern void objUpdateOpacity(int);
    extern int ObjHits_GetPriorityHit(int, int, int, int);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern u8 lbl_803DDCE8;
    extern f32 timeDelta;
    extern f32 lbl_803E63E0;
    extern int lbl_802C2510[];
    typedef struct
    {
        int m0;
        int m1;
        int m2;
        int m3;
    } TorchPrm;
    DfpTorchState* blob = ((GameObject*)obj)->extra;
    void* res;
    int h;
    int i;
    f32 buf[5];
    TorchPrm prm;

    prm = *(TorchPrm*)lbl_802C2510;
    Sfx_PlayFromObject(obj, 0x72);
    objUpdateOpacity(obj);
    switch (blob->mode)
    {
    case 0:
        break;
    case 1:
        buf[4] = lbl_803E63E0;
        blob->prevLit = blob->lit;
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            blob->lit = 1 - blob->lit;
            if (blob->lit != 0)
            {
                blob->litTimer = 0x7d0;
            }
        }
        if (blob->lit != 0)
        {
            h = blob->litTimer;
            if (h != 0)
            {
                blob->litTimer -= (s16)timeDelta;
                if (blob->litTimer <= 0)
                {
                    blob->litTimer = 0;
                    blob->lit = 0;
                }
            }
        }
        if (blob->lit != 0 && blob->flickerTimer <= 0 && blob->sfxPending != 0)
        {
            blob->sfxPending = 0;
            Sfx_PlayFromObject(obj, 0x80);
        }
        if (blob->lit != blob->prevLit)
        {
            if (blob->lit != 0)
            {
                res = Resource_Acquire(0x69, 1);
                prm.m1 = blob->colorIdx * 2 + 0x19d;
                prm.m2 = blob->colorIdx * 2 + 0x19e;
                (*(void (*)(int, int, f32*, int, int, void*))(*(int*)(*(int*)res + 4)))(obj, 1, buf, 0x10004, -1, &prm);
                Resource_Release(res);
                for (i = 0; i < 0x64; i++)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x1a3, NULL, 0, -1,
                                                     NULL);
                }
                if (blob->gameBit != -1)
                {
                    if (GameBit_Get(blob->gameBit) == 0)
                    {
                        GameBit_Set(blob->gameBit, 1);
                    }
                }
                if ((s8)lbl_803DDCE8 == 0 && blob->colorIdx == 0 && GameBit_Get(blob->gameBit) != 0)
                {
                    lbl_803DDCE8 = 1;
                }
                if ((s8)lbl_803DDCE8 == 1 && blob->colorIdx == 1 && GameBit_Get(blob->gameBit) != 0)
                {
                    GameBit_Set(0x5e2, 1);
                    lbl_803DDCE8 = 2;
                }
                blob->sfxPending = 1;
                blob->flickerTimer = 1;
            }
            else
            {
                Sfx_StopObjectChannel(obj, 0x40);
                (*gModgfxInterface)->detachSource((void*)obj);
                (*gExpgfxInterface)->freeSource((u32)obj);
                if (blob->gameBit != -1)
                {
                    if (GameBit_Get(blob->gameBit) != 0)
                    {
                        GameBit_Set(blob->gameBit, 0);
                    }
                }
                if ((s8)lbl_803DDCE8 == 1 && blob->colorIdx == 0)
                {
                    lbl_803DDCE8 = 0;
                }
                if ((s8)lbl_803DDCE8 == 2 && blob->colorIdx == 1 && GameBit_Get(0x5e2) == 0)
                {
                    GameBit_Set(0x5e2, 0);
                    lbl_803DDCE8 = 0;
                }
            }
        }
        break;
    }
}

void drakorenergy_update(int obj);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
