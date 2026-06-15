#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
#include "main/main.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

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

extern void DBstealerwo_setFuncPtrs_80203c78(void);
extern void fn_802960E8(void* playerObj, int p2);
extern f32 timeDelta;
extern s16 lbl_80329848[];
extern int dbstealerworm_stateHandlerB06();
extern void unlockLevel(int a, int b, int c);
extern void Music_Trigger(int a, int b);

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
    uint portBusy;
    int target;
    short* port;
    int control;
    double dist;
    undefined4 msgNear_0;
    undefined4 msgNear_1;
    undefined4 msgNear_2;
    undefined4 msgGiveup_0;
    undefined4 msgGiveup_1;
    undefined4 msgGiveup_2;
    undefined4 msgArrive_0;
    undefined4 msgArrive_1;
    undefined4 msgArrive_2;
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
            msgNear_2 = *(undefined4*)(param_10 + 0x2d0);
            port = *(short**)(control + 0x24);
            msgNear_0 = 0xe;
            msgNear_1 = 1;
            portBusy = FUN_80006ab8(port);
            if (portBusy == 0)
            {
                FUN_80006ac4(port, (uint) & msgNear_0);
            }
            *(undefined*)(control + 0x34) = 1;
        }
    }
    else
    {
        port = *(short**)(control + 0x24);
        msgArrive_0 = 9;
        msgArrive_1 = 0;
        msgArrive_2 = 0x24;
        portBusy = FUN_80006ab8(port);
        if (portBusy == 0)
        {
            FUN_80006ac4(port, (uint) & msgArrive_0);
        }
        *(undefined*)(control + 0x34) = 1;
        msgGiveup_2 = *(undefined4*)(param_10 + 0x2d0);
        port = *(short**)(control + 0x24);
        msgGiveup_0 = 7;
        msgGiveup_1 = 1;
        portBusy = FUN_80006ab8(port);
        if (portBusy == 0)
        {
            FUN_80006ac4(port, (uint) & msgGiveup_0);
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
    int subState;
    uint sfxIndex;
    short* port;
    int control;
    undefined4 msg_2;
    undefined4 msg_1;
    undefined4 msg_0;

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
        subState = FUN_80017a98();
        subState = (**(code**)(**(int**)(*(int*)(subState + 200) + 0x68) + 0x44))();
        if (subState == 0)
        {
            sfxIndex = randomGetRange(0, 2);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + sfxIndex * 4));
        }
        else
        {
            sfxIndex = randomGetRange(3, 4);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + sfxIndex * 4));
        }
        msg_0 = *(undefined4*)(control + 0x30);
        msg_1 = *(undefined4*)(control + 0x2c);
        port = *(short**)(control + 0x24);
        msg_2 = *(undefined4*)(control + 0x28);
        sfxIndex = FUN_80006ab8(port);
        if (sfxIndex == 0)
        {
            FUN_80006ac4(port, (uint) & msg_2);
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
    undefined4 noTarget;
    int control;

    control = *(int*)&((GameObject*)param_9)->extra;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    noTarget = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, noTarget, param_13, param_14, param_15, param_16);
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
    undefined4 noTarget;

    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    noTarget = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    ((BaddieState*)param_10)->moveSpeed = lbl_803E6F8C;
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, noTarget, param_13, param_14, param_15, param_16);
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
    uint pick;
    undefined4 noTarget;
    int extra;
    int control;

    extra = *(int*)&((GameObject*)param_9)->extra;
    control = *(int*)(extra + 0x40c);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    noTarget = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
    {
        pick = randomGetRange(0, 1);
        if (pick == 0)
        {
            if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, noTarget, param_13, param_14, param_15, param_16);
                ((BaddieState*)param_10)->moveDone = 0;
            }
        }
        else if (*(s8*)&((BaddieState*)param_10)->moveJustStartedA != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, noTarget, param_13, param_14, param_15, param_16);
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
    int sub;
    double absDelta;
    double signedDelta;
    float out[5];

    sub = *(int*)(param_5 + 0x5c);
    yawDelta = Obj_GetYawDeltaToObject(param_5, param_6, out);
    if ((double)lbl_803E6F40 == param_4)
    {
        result = 0;
    }
    else
    {
        signedDelta = (double)(float)((double)(float)((double)out[0] - param_1) / param_4);
        absDelta = signedDelta;
        if (signedDelta < (double)lbl_803E6F40)
        {
            absDelta = -signedDelta;
        }
        if ((double)lbl_803E7008 <= absDelta)
        {
            if (signedDelta < (double)lbl_803E6F40)
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
FUN_80202130(double param_1, double param_2, undefined8 param_3, double param_4, ushort* param_5,
             int param_6)
{
    int yawDelta;
    int sub;
    double heightDiff;
    float out[7];

    sub = *(int*)(param_5 + 0x5c);
    if ((param_5 != (ushort*)0x0) && (param_6 != 0))
    {
        yawDelta = Obj_GetYawDeltaToObject(param_5, param_6, out);
        if ((double)lbl_803E6F40 != param_4)
        {
            if ((double)out[0] < param_1)
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

void fn_80204320(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern u8 lbl_803DC182;
    extern s16 lbl_80329848[];
    DfpLevelControlState* sub;
    void* player;

    sub = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (lbl_803DC182 != 0)
    {
        s16 i;
        s16* arr = (s16*)((char*)lbl_80329848 + 12);
        arr[0] = 0;
        arr[1] = 0;
        arr[2] = 0;
        arr = lbl_80329848;
        for (i = 0; i < 6; i++)
        {
            *arr = (s16)randomGetRange(1, 4);
            arr++;
        }
        GameBit_Set(1508, 0);
        sub->timer = 0;
        lbl_803DC182 = 0;
    }
    if (GameBit_Get(1507) == 0)
    {
        if (GameBit_Get(1504) != 0 && GameBit_Get(1505) != 0)
        {
            GameBit_Set(1507, 1);
        }
    }
    if (GameBit_Get(3671) == 0)
    {
        if (GameBit_Get(1589) != 0 && sub->sfxLatch == 0)
        {
            s16 i;
            s16* arr;
            Sfx_PlayFromObject(0, 1095);
            for (i = 0, arr = lbl_80329848; i < 6; i++)
            {
                *arr = (s16)randomGetRange(1, 4);
                arr++;
            }
            GameBit_Set(1508, 1);
            sub->sfxLatch = 1;
        }
        else if (GameBit_Get(1589) == 0 && sub->sfxLatch == 1)
        {
            sub->sfxLatch = 0;
            GameBit_Set(1508, 0);
        }
        if (GameBit_Get(1509) != 0)
        {
            sub->timer = 300;
            ObjMsg_SendToObject(player, 0x60005, obj, 1);
        }
    }
}

void dll_22C_init(int obj, char* p);

void dfplevelcontrol_render(void)
{
}

void dfplevelcontrol_hitDetect(void)
{
}

void dfplevelcontrol_release(void)
{
}

void dfpobjcreator_hitDetect(void);

int dfplevelcontrol_getExtraSize(void) { return 0xc; }
int dfplevelcontrol_getObjectTypeId(void) { return 0x0; }
int dfpobjcreator_getExtraSize(void);

void dfplevelcontrol_free(int x) { extern undefined8 ObjGroup_RemoveObject(); /* #57 */ ObjGroup_RemoveObject(x, 0x9); }

int dfplevelcontrol_SeqFn(int p1)
{
    extern void* Obj_GetPlayerObject(void); /* #57 */
    DfpLevelControlState* p_b8 = ((GameObject*)p1)->extra;
    void* player = Obj_GetPlayerObject();
    s16 v = p_b8->timer;
    if (v > 0)
    {
        p_b8->timer -= (s16)timeDelta;
        fn_802960E8(player, 0x51e);
    }
    return 0;
}

void dfplevelcontrol_initialise(void)
{
    s16* p = lbl_80329848;
    p[0] = 1;
    p[1] = 2;
    p[2] = 3;
    p[3] = 0;
    p[4] = 0;
    p[5] = 0;
    p[6] = 0;
    p[7] = 0;
    p[8] = 0;
}

void dfpobjcreator_free(int obj, int flag);

void dfplevelcontrol_setScale(int unused, u8* out)
{
    s16 i = 0;
    s16* p = lbl_80329848;
    for (; i < 9; i += 3)
    {
        out[i] = p[0];
        out[(s16)(i + 1)] = p[1];
        out[(s16)(i + 2)] = p[2];
        p += 3;
    }
}

int dbstealerworm_stateHandlerA00(int obj, int p2);

void DBstealerwo_setFuncPtrs_80203c78(void);

void dfplevelcontrol_init(int obj, int param2)
{
    extern undefined4 ObjGroup_AddObject(); /* #57 */
    DfpLevelControlState* state = ((GameObject*)obj)->extra;
    int v;
    ObjGroup_AddObject(obj, 9);
    ((DfpFlags7*)&state->flags07)->b80 = GameBit_Get(0xd5d);
    ((DfpFlags7*)&state->flags07)->b40 = GameBit_Get(0xd59);
    ((DfpFlags7*)&state->flags07)->b20 = GameBit_Get(0xd5a);
    ((GameObject*)obj)->animEventCallback = (void*)dfplevelcontrol_SeqFn;
    state->mode = 1;
    v = *(s16*)(param2 + 0x1a);
    if (v != 0 && v <= 2)
    {
        state->mode = v;
    }
    (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    unlockLevel(0, 0, 1);
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x4000;
    if (((GameObject*)obj)->anim.mapEventSlot == 0x15)
    {
        GameBit_Set(0xdce, 0);
    }
    if ((u32)GameBit_Get(0xdce) != 0)
    {
        Music_Trigger(0x37, 0);
        Music_Trigger(0xe4, 0);
    }
}

void dfplevelcontrol_update(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern void Sfx_PlayFromObject(int, u16);
    extern void coordsToMapCell(f32, f32);
    extern void fn_80204098(int);
    extern void SCGameBitLatch_Update(void*, int, int, int, int, int);
    extern void SCGameBitLatch_UpdateInverted(void*, int, int, int, int, int);
    extern s16 lbl_803DC180;
    extern f32 timeDelta;
    DfpLevelControlState* state = ((GameObject*)obj)->extra;
    char* player;
    u8 b1;
    u8 b2;
    u8 b3;
    int mode;

    player = Obj_GetPlayerObject();
    b1 = GameBit_Get(0xd5d);
    b2 = GameBit_Get(0xd59);
    b3 = GameBit_Get(0xd5a);
    if ((b1 != 0 && ((u32)state->flags07 >> 7 & 1) == 0)
        || (b2 != 0 && ((u32)state->flags07 >> 6 & 1) == 0)
        || (b3 != 0 && ((u32)state->flags07 >> 5 & 1) == 0))
    {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    ((DfpFlags7*)&state->flags07)->b80 = b1;
    ((DfpFlags7*)&state->flags07)->b40 = b2;
    ((DfpFlags7*)&state->flags07)->b20 = b3;
    if (GameBit_Get(0x5e8) == 0 && GameBit_Get(0x5ee) != 0 && GameBit_Get(0x5ef) != 0)
    {
        GameBit_Set(0x5e8, 1);
    }
    coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ);
    mode = (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    switch (mode)
    {
    case 1:
        if (lbl_803DC180 != 0)
        {
            lbl_803DC180 -= (s16)timeDelta;
            if (lbl_803DC180 <= 0)
            {
                lbl_803DC180 = 0;
            }
        }
        fn_80204320(obj);
        break;
    case 2:
        fn_80204098(obj);
        break;
    case 4:
        break;
    }
    SCGameBitLatch_Update((void*)state->unk08, 2, -1, -1, 0xdce, 0x95);
    SCGameBitLatch_UpdateInverted((void*)state->unk08, 4, -1, -1, 0xdce, 0x37);
    SCGameBitLatch_UpdateInverted((void*)state->unk08, 1, -1, -1, 0xdce, 0xe4);
    GameBit_Set(0xdcf, 0);
}

int fn_80202A2C(int obj, int* objs, f32* weights, int n, f32 limit);

void fn_80204098(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern void Sfx_PlayFromObject(int, u16);
    extern void ObjMsg_SendToObject(void*, int, int, int);
    extern u8 lbl_803DC183;
    extern s16 lbl_80329848[];
    DfpLevelControlState* state = ((GameObject*)obj)->extra;
    void* player;
    s16 i;
    s16* p;

    player = Obj_GetPlayerObject();
    if (lbl_803DC183 != 0)
    {
        GameBit_Set(0x2d, 1);
        GameBit_Set(0x1d7, 1);
        for (i = 0, p = lbl_80329848; i < 9; i++)
        {
            *p = (s16)randomGetRange(1, 4);
            p++;
        }
        GameBit_Set(0x5e4, 0);
        state->timer = 0;
        lbl_803DC183 = 0;
    }
    if (GameBit_Get(0x5e3) == 0 && GameBit_Get(0x5e0) != 0 && GameBit_Get(0x5e1) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmn_spithit6);
        GameBit_Set(0x5e3, 1);
    }
    if (GameBit_Get(0x792) == 0 && GameBit_Get(0xb8c) != 0 && GameBit_Get(0xb8c) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmn_spithit6);
        GameBit_Set(0x792, 1);
    }
    if (GameBit_Get(0xe58) == 0)
    {
        if (GameBit_Get(0x635) != 0 && state->sfxLatch == 0)
        {
            Sfx_PlayFromObject(0, SFXfoot_wood_run_2);
            for (i = 0, p = lbl_80329848; i < 9; i++)
            {
                *p = (s16)randomGetRange(1, 4);
                p++;
            }
            GameBit_Set(0x5e4, 1);
            state->sfxLatch = 1;
        }
        else
        {
            if (GameBit_Get(0x635) == 0 && state->sfxLatch == 1)
            {
                state->sfxLatch = 0;
                GameBit_Set(0x5e4, 0);
            }
        }
        if (GameBit_Get(0x5e5) != 0)
        {
            state->timer = 300;
            ObjMsg_SendToObject(player, 0x60005, obj, 0);
        }
    }
    if (GameBit_Get(0x7a1) != 0)
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6) == 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6, 1);
        }
    }
}

int dbstealerworm_stateHandlerB06(int obj, int p2);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
