/* DLL 0x22A - DFP object creator [801FE118-801FEB30) */
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

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* plain forwarder. */

/* fn_X(lbl); lbl = 0; */

/* dll_224_hitDetect: render iff obj->field_0x74 set. */

/* dll_224_update: dispatch GameEvent id based on vtable[0x40](obj->field_0xac). */

/* fn_801FD4A8: decrement extra->[4] by x; return whether it reached 0. */

/* dbegg_setupFromDef: set up dbegg from def fields, dispatch on def->_26 mode byte. */

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

typedef struct DfpobjcreatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;
    u8 pad1A[0x1C - 0x1A];
    s16 spawnPeriod;
    u8 pad1E[0x24 - 0x1E];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DfpobjcreatorObjectDef;

typedef struct DfpobjcreatorPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DfpobjcreatorPlacement;

/* Obj_AllocObjectSetup(0x24,...) spawn buffer composed in
 * dbstealerworm_stateHandlerA00. Head is the common ObjPlacement (the
 * 0x04..0x07 bytes live in ObjPlacement.unk04); tail (0x18..0x23) is
 * file-local. */
typedef struct DfpobjcreatorSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    u8 pad18[0x1A - 0x18];
    s16 unk1A;         /* 0x1A */
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;         /* 0x1E */
    s16 unk20;         /* 0x20 */
    u8 pad22[0x24 - 0x22];
} DfpobjcreatorSetup;

STATIC_ASSERT(offsetof(DfpobjcreatorSetup, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(DfpobjcreatorSetup, unk1E) == 0x1E);
STATIC_ASSERT(offsetof(DfpobjcreatorSetup, unk20) == 0x20);
STATIC_ASSERT(sizeof(DfpobjcreatorSetup) == 0x24);

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

extern void Obj_FreeObject(int obj);
extern f32 timeDelta;
extern int dbstealerworm_stateHandlerA02();

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
    float scale;
    uint queueFull;
    int target;
    short* msgQueue;
    int control;
    double dist;
    undefined4 msgA_arg0;
    undefined4 msgA_arg1;
    undefined4 msgA_arg2;
    undefined4 msgC_arg0;
    undefined4 msgC_arg1;
    undefined4 msgC_arg2;
    undefined4 msgB_arg0;
    undefined4 msgB_arg1;
    undefined4 msgB_arg2;
    float dx;
    float dy;
    float dz;

    control = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    *(byte*)(control + 0x15) = *(byte*)(control + 0x15) & 0xfb;
    scale = lbl_803E6F88;
    ((BaddieState*)param_10)->animSpeedA = ((BaddieState*)param_10)->animSpeedA / lbl_803E6F88;
    ((BaddieState*)param_10)->animSpeedB = ((BaddieState*)param_10)->animSpeedB / scale;
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
            msgA_arg0 = 0xe;
            msgA_arg1 = 1;
            queueFull = FUN_80006ab8(msgQueue);
            if (queueFull == 0)
            {
                FUN_80006ac4(msgQueue, (uint) & msgA_arg0);
            }
            *(undefined*)(control + 0x34) = 1;
        }
    }
    else
    {
        msgQueue = *(short**)(control + 0x24);
        msgB_arg0 = 9;
        msgB_arg1 = 0;
        msgB_arg2 = 0x24;
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgB_arg0);
        }
        *(undefined*)(control + 0x34) = 1;
        msgC_arg2 = *(undefined4*)(param_10 + 0x2d0);
        msgQueue = *(short**)(control + 0x24);
        msgC_arg0 = 7;
        msgC_arg1 = 1;
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgC_arg0);
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
    int isStanding;
    uint queueFull;
    short* msgQueue;
    int control;
    undefined4 msg_arg0;
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
        isStanding = FUN_80017a98();
        isStanding = (**(code**)(**(int**)(*(int*)(isStanding + 200) + 0x68) + 0x44))();
        if (isStanding == 0)
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
        msg_arg0 = *(undefined4*)(control + 0x28);
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msg_arg0);
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
    undefined4 animArg;
    int control;

    control = *(int*)&((GameObject*)param_9)->extra;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    animArg = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, animArg, param_13, param_14, param_15, param_16);
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
    undefined4 animArg;

    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    animArg = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, animArg, param_13, param_14, param_15, param_16);
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
    uint randomChoice;
    undefined4 animArg;
    int extra;
    int control;

    extra = *(int*)&((GameObject*)param_9)->extra;
    control = *(int*)(extra + 0x40c);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    animArg = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        randomChoice = randomGetRange(0, 1);
        if (randomChoice == 0)
        {
            if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, animArg, param_13, param_14, param_15, param_16);
                ((BaddieState*)param_10)->moveDone = 0;
            }
        }
        else if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, animArg, param_13, param_14, param_15, param_16);
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
    int yaw;
    undefined4 result;
    int stateBase;
    double absRatio;
    double ratio;
    float outVec[5];

    stateBase = *(int*)(param_5 + 0x5c);
    yaw = Obj_GetYawDeltaToObject(param_5, param_6, outVec);
    if ((double)lbl_803E6F40 == param_4)
    {
        result = 0;
    }
    else
    {
        ratio = (double)(float)((double)(float)((double)outVec[0] - param_1) / param_4);
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
            *(float*)(stateBase + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yaw ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(stateBase + 0x280)) +
                *(float*)(stateBase + 0x280);
            *(float*)(stateBase + 0x284) = lbl_803E6F40;
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
    int yaw;
    int stateBase;
    double deltaY;
    float outVec[7];

    stateBase = *(int*)(param_5 + 0x5c);
    if ((param_5 != (ushort*)0x0) && (param_6 != 0))
    {
        yaw = Obj_GetYawDeltaToObject(param_5, param_6, outVec);
        if ((double)lbl_803E6F40 != param_4)
        {
            if ((double)outVec[0] < param_1)
            {
                deltaY = (double)(*(float*)(param_5 + 8) - *(float*)(param_6 + 0x10));
                if (deltaY < (double)lbl_803E6F40)
                {
                    deltaY = -deltaY;
                }
                if (deltaY < (double)lbl_803E7010)
                {
                    return 1;
                }
            }
            *(float*)(stateBase + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yaw ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(stateBase + 0x280)) +
                *(float*)(stateBase + 0x280);
            *(float*)(stateBase + 0x284) = lbl_803E6F40;
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

void dfpobjcreator_hitDetect(void)
{
}

void dfpobjcreator_release(void)
{
}

void dfpobjcreator_initialise(void)
{
}

void dll_22C_hitDetect_nop(void);

int dfpobjcreator_getExtraSize(void) { return 0x1c; }
int dfpobjcreator_getObjectTypeId(void) { return 0x0; }
int dll_22C_SeqFn(void);

void dfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void dfpobjcreator_free(int obj, int flag)
{
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    if (flag == 0)
    {
        if (*(void**)&state->spawnedObj != NULL)
        {
            Obj_FreeObject(state->spawnedObj);
            state->spawnedObj = 0;
        }
    }
}

void dbegg_init(int obj);

void dfpobjcreator_init(int obj, s8* def)
{
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)def[0x1E] << 8);
    state->gameBit = ((DfpobjcreatorObjectDef*)def)->gameBit;
    state->spawnPeriod = ((DfpobjcreatorObjectDef*)def)->spawnPeriod;
    state->spawnTimer = state->spawnPeriod;
    state->unk12 = (s16)(s32)
    def[0x1F];
    state->unk14 = (s16)((s32)(u8)def[0x20] << 1);
    state->unk16 = 100;
}

void dfplevelcontrol_setScale(int unused, u8* out);

#pragma dont_inline on

void dfpobjcreator_update(int obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern uint GameBit_Get(int);
    extern u8*Obj_AllocObjectSetup(int, int);
    extern u8*Obj_SetupObject(u8*, int, int, int, int);
    extern f32 timeDelta;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    u8* setup;
    u8* newObj;

    if (Obj_IsLoadingLocked() != 0)
    {
        switch (((DfpobjcreatorPlacement*)data)->unk1A)
        {
        case 7:
            state->spawnTimer -= (s16)timeDelta;
            if (state->spawnTimer <= 0 && GameBit_Get(state->gameBit) != 0)
            {
                state->spawnTimer = state->spawnPeriod;
                setup = Obj_AllocObjectSetup(0x24, 0x71b);
                ((DfpobjcreatorSetup*)setup)->base.posX = ((DfpobjcreatorPlacement*)data)->posX;
                ((DfpobjcreatorSetup*)setup)->base.posY = ((DfpobjcreatorPlacement*)data)->posY;
                ((DfpobjcreatorSetup*)setup)->base.posZ = ((DfpobjcreatorPlacement*)data)->posZ;
                ((DfpobjcreatorSetup*)setup)->base.unk04[0] = ((DfpobjcreatorPlacement*)data)->unk4;
                ((DfpobjcreatorSetup*)setup)->base.unk04[1] = ((DfpobjcreatorPlacement*)data)->unk5;
                ((DfpobjcreatorSetup*)setup)->base.unk04[2] = ((DfpobjcreatorPlacement*)data)->unk6;
                ((DfpobjcreatorSetup*)setup)->base.unk04[3] = ((DfpobjcreatorPlacement*)data)->unk7;
                ((DfpobjcreatorSetup*)setup)->unk1E = -1;
                ((DfpobjcreatorSetup*)setup)->unk20 = -1;
                ((DfpobjcreatorSetup*)setup)->unk1A = 0xdc;
                newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                         *(int*)&((GameObject*)obj)->anim.parent);
                ((GameObject*)newObj)->unkF4 = *(s8*)(data + 0x1e);
            }
            break;
        }
    }
}
#pragma dont_inline reset

int dbstealerworm_stateHandlerA02(int obj, int p2);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
