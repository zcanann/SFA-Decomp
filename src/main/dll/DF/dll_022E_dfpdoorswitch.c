/* DLL 0x22E — DFP door switch object [801FE118-801FEB30) */
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"

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

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/anim.h"
#include "main/dll/baddie_state.h"

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

extern void OSReport(const char* fmt, ...);

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
    float scaleDiv;
    uint isQueued;
    int targetObj;
    short* msgPort;
    int control;
    double dist;
    undefined4 msgA_id;
    undefined4 msgA_arg;
    undefined4 msgA_target;
    undefined4 msgD_id;
    undefined4 msgD_arg;
    undefined4 msgB_target;
    undefined4 msgC_id;
    undefined4 msgC_arg;
    undefined4 msgC_extra;
    float dx;
    float dy;
    float dz;

    control = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    *(byte*)(control + 0x15) = *(byte*)(control + 0x15) & 0xfb;
    scaleDiv = lbl_803E6F88;
    ((BaddieState*)param_10)->animSpeedA = ((BaddieState*)param_10)->animSpeedA / lbl_803E6F88;
    ((BaddieState*)param_10)->animSpeedB = ((BaddieState*)param_10)->animSpeedB / scaleDiv;
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
        targetObj = *(int*)(param_10 + 0x2d0);
        dx = *(float*)(targetObj + 0xc) - ((GameObject*)param_9)->anim.localPosX;
        dy = *(float*)(targetObj + 0x10) - (((GameObject*)param_9)->anim.localPosY + lbl_803E6F94);
        dz = *(float*)(targetObj + 0x14) - ((GameObject*)param_9)->anim.localPosZ;
        dist = FUN_80293900((double)(dz * dz + dx * dx + dy * dy));
        if (dist < (double)lbl_803E6F50)
        {
            msgA_target = *(undefined4*)(param_10 + 0x2d0);
            msgPort = *(short**)(control + 0x24);
            msgA_id = 0xe;
            msgA_arg = 1;
            isQueued = FUN_80006ab8(msgPort);
            if (isQueued == 0)
            {
                FUN_80006ac4(msgPort, (uint) & msgA_id);
            }
            *(undefined*)(control + 0x34) = 1;
        }
    }
    else
    {
        msgPort = *(short**)(control + 0x24);
        msgC_id = 9;
        msgC_arg = 0;
        msgC_extra = 0x24;
        isQueued = FUN_80006ab8(msgPort);
        if (isQueued == 0)
        {
            FUN_80006ac4(msgPort, (uint) & msgC_id);
        }
        *(undefined*)(control + 0x34) = 1;
        msgB_target = *(undefined4*)(param_10 + 0x2d0);
        msgPort = *(short**)(control + 0x24);
        msgD_id = 7;
        msgD_arg = 1;
        isQueued = FUN_80006ab8(msgPort);
        if (isQueued == 0)
        {
            FUN_80006ac4(msgPort, (uint) & msgD_id);
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
    int sfxVariant;
    uint isQueued;
    short* msgPort;
    int control;
    undefined4 msgWord2;
    undefined4 msgWord1;
    undefined4 msgWord0;

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
        sfxVariant = FUN_80017a98();
        sfxVariant = (**(code**)(**(int**)(*(int*)(sfxVariant + 200) + 0x68) + 0x44))();
        if (sfxVariant == 0)
        {
            isQueued = randomGetRange(0, 2);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + isQueued * 4));
        }
        else
        {
            isQueued = randomGetRange(3, 4);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + isQueued * 4));
        }
        msgWord0 = *(undefined4*)(control + 0x30);
        msgWord1 = *(undefined4*)(control + 0x2c);
        msgPort = *(short**)(control + 0x24);
        msgWord2 = *(undefined4*)(control + 0x28);
        isQueued = FUN_80006ab8(msgPort);
        if (isQueued == 0)
        {
            FUN_80006ac4(msgPort, (uint) & msgWord2);
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
    undefined4 animId;
    int control;

    control = *(int*)&((GameObject*)param_9)->extra;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, animId, param_13, param_14, param_15, param_16);
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
    undefined4 animId;

    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, animId, param_13, param_14, param_15, param_16);
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
    uint animChoice;
    undefined4 animId;
    int objExtra;
    int control;

    objExtra = *(int*)&((GameObject*)param_9)->extra;
    control = *(int*)(objExtra + 0x40c);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        animChoice = randomGetRange(0, 1);
        if (animChoice == 0)
        {
            if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, animId, param_13, param_14, param_15, param_16);
                ((BaddieState*)param_10)->moveDone = 0;
            }
        }
        else if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, animId, param_13, param_14, param_15, param_16);
            ((BaddieState*)param_10)->moveDone = 0;
        }
        ((BaddieState*)param_10)->unk34D = 1;
        ((BaddieState*)param_10)->moveSpeed =
            lbl_803E6FDC +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(objExtra + 0x406)) - DOUBLE_803e6f78) /
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
    int seqData;
    double absRatio;
    double ratio;
    float yawOut[5];

    seqData = *(int*)(param_5 + 0x5c);
    yawDelta = Obj_GetYawDeltaToObject(param_5, param_6, yawOut);
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
            *(float*)(seqData + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(seqData + 0x280)) +
                *(float*)(seqData + 0x280);
            *(float*)(seqData + 0x284) = lbl_803E6F40;
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
    int seqData;
    double heightDiff;
    float yawOut[7];

    seqData = *(int*)(param_5 + 0x5c);
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
            *(float*)(seqData + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(seqData + 0x280)) +
                *(float*)(seqData + 0x280);
            *(float*)(seqData + 0x284) = lbl_803E6F40;
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

void doorswitch_render(void)
{
}

void doorswitch_hitDetect(void)
{
}

void doorswitch_release(void)
{
}

void doorswitch_initialise(void)
{
}


int doorswitch_getExtraSize(void) { return 0x0; }
int doorswitch_getObjectTypeId(void) { return 0x0; }

void doorswitch_free(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_update(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_init(void) { OSReport(sDoorswitchInitNoLongerSupported); }


/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
