/* DLL 0x0240 — GC robot-blast objects [801FE118-801FEB30) */
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

extern u8 lbl_80329514[];
extern f32 timeDelta;

int GCRobotBlast_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void objfx_spawnDirectionalBurst(int, int, f32, int, int, int, f32, int, int);
    extern f32 lbl_803E6270;
    extern f32 lbl_803E6274;
    
    int sub = *(int*)&((GameObject*)obj)->extra;
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        ((BlastFlags4*)&((GCRobotBlastState*)sub)->flags04)->b80 = animUpdate->eventIds[i];
    }
    if (((u32)((GCRobotBlastState*)sub)->flags04 >> 7 & 1) != 0)
    {
        switch (((GCRobotBlastState*)sub)->mode)
        {
        case 0:
        case 1:
            objfx_spawnDirectionalBurst(obj, 7, lbl_803E6270, 5, 6, 0x64, lbl_803E6274, 0, 0x200000);
            objfx_spawnDirectionalBurst(obj, 6, lbl_803E6270, 1, 6, 0x64, lbl_803E6274, 0, 0x200000);
            break;
        }
    }
    return 0;
}

int dbstealerworm_stateHandlerB04(int obj, int p);

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
    *(float*)(param_10 + 0x2a0) = lbl_803E6F80;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 0x1f;
    if (*(char*)(param_10 + 0x27a) != '\0')
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
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float speedDiv;
    uint busy;
    int target;
    short* msgQueue;
    int control;
    double dist;
    undefined4 msgWord48;
    undefined4 msgWord44;
    undefined4 msgWord40;
    undefined4 msgWord3c;
    undefined4 msgWord38;
    undefined4 msgWord34;
    undefined4 msgWord30;
    undefined4 msgWord2c;
    undefined4 msgWord28;
    float dx;
    float dy;
    float dz;

    control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    *(byte*)(control + 0x15) = *(byte*)(control + 0x15) & 0xfb;
    speedDiv = lbl_803E6F88;
    *(float*)(state + 0x280) = *(float*)(state + 0x280) / lbl_803E6F88;
    *(float*)(state + 0x284) = *(float*)(state + 0x284) / speedDiv;
    *(float*)(state + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 0x1f;
    if ((((GameObject*)obj)->anim.currentMoveProgress <= lbl_803E6F84) ||
        (((GameObject*)obj)->anim.localPosY < *(float*)(*(int*)(state + 0x2d0) + 0x10) - lbl_803E6F90))
    {
        target = *(int*)(state + 0x2d0);
        dx = *(float*)(target + 0xc) - ((GameObject*)obj)->anim.localPosX;
        dy = *(float*)(target + 0x10) - (((GameObject*)obj)->anim.localPosY + lbl_803E6F94);
        dz = *(float*)(target + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        dist = FUN_80293900((double)(dz * dz + dx * dx + dy * dy));
        if (dist < (double)lbl_803E6F50)
        {
            msgWord40 = *(undefined4*)(state + 0x2d0);
            msgQueue = *(short**)(control + 0x24);
            msgWord48 = 0xe;
            msgWord44 = 1;
            busy = FUN_80006ab8(msgQueue);
            if (busy == 0)
            {
                FUN_80006ac4(msgQueue, (uint) & msgWord48);
            }
            *(undefined*)(control + 0x34) = 1;
        }
    }
    else
    {
        msgQueue = *(short**)(control + 0x24);
        msgWord30 = 9;
        msgWord2c = 0;
        msgWord28 = 0x24;
        busy = FUN_80006ab8(msgQueue);
        if (busy == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgWord30);
        }
        *(undefined*)(control + 0x34) = 1;
        msgWord34 = *(undefined4*)(state + 0x2d0);
        msgQueue = *(short**)(control + 0x24);
        msgWord3c = 7;
        msgWord38 = 1;
        busy = FUN_80006ab8(msgQueue);
        if (busy == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgWord3c);
        }
        *(undefined*)(control + 0x34) = 1;
    }
    return 0;
}

undefined4
FUN_80201260(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int playerInjured;
    uint sfxIdx;
    short* msgQueue;
    int control;
    undefined4 msgWord28;
    undefined4 msgWord24;
    undefined4 msgWord20;

    control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(char*)(state + 0x27a) != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        *(undefined4*)(state + 0x2d0) = 0;
        if (*(int*)(control + 0x18) != 0)
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                *(int*)(control + 0x18), 0x11, obj, 0x10, param_13, param_14, param_15, param_16);
            *(undefined4*)(control + 0x18) = 0;
        }
        playerInjured = FUN_80017a98();
        playerInjured = (**(code**)(**(int**)(*(int*)(playerInjured + 200) + 0x68) + 0x44))();
        if (playerInjured == 0)
        {
            sfxIdx = randomGetRange(0, 2);
            FUN_80006824(obj, (ushort) * (undefined4*)(&DAT_8032a290 + sfxIdx * 4));
        }
        else
        {
            sfxIdx = randomGetRange(3, 4);
            FUN_80006824(obj, (ushort) * (undefined4*)(&DAT_8032a290 + sfxIdx * 4));
        }
        msgWord20 = *(undefined4*)(control + 0x30);
        msgWord24 = *(undefined4*)(control + 0x2c);
        msgQueue = *(short**)(control + 0x24);
        msgWord28 = *(undefined4*)(control + 0x28);
        sfxIdx = FUN_80006ab8(msgQueue);
        if (sfxIdx == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgWord28);
        }
        *(undefined4*)(control + 0x3c) = 0;
    }
    *(undefined*)(state + 0x34d) = 0x10;
    *(float*)(state + 0x2a0) = lbl_803E6FD8;
    *(float*)(state + 0x280) = lbl_803E6F40;
    if (*(char*)(state + 0x346) != '\0')
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
    undefined4 noMove;
    int control;

    control = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    noMove = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    *(float*)(param_10 + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, noMove, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    control = *(int*)(control + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
        *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 1;
    }
    if (*(char*)(param_10 + 0x346) != '\0')
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
    undefined4 noMove;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    noMove = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    *(float*)(param_10 + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, noMove, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
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
    undefined4 noMove;
    int extra;
    int control;

    extra = *(int*)&((GameObject*)param_9)->extra;
    control = *(int*)(extra + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    noMove = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        pick = randomGetRange(0, 1);
        if (pick == 0)
        {
            if (*(char*)(param_10 + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, noMove, param_13, param_14, param_15, param_16);
                *(undefined*)(param_10 + 0x346) = 0;
            }
        }
        else if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, noMove, param_13, param_14, param_15, param_16);
            *(undefined*)(param_10 + 0x346) = 0;
        }
        *(undefined*)(param_10 + 0x34d) = 1;
        *(float*)(param_10 + 0x2a0) =
            lbl_803E6FDC +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e6f78) /
            lbl_803E6FE0;
    }
    *(float*)(param_10 + 0x280) = lbl_803E6F40;
    if (*(char*)(param_10 + 0x346) != '\0')
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
    int anim;
    double absRate;
    double turnRate;
    float yawOut[5];

    anim = *(int*)(param_5 + 0x5c);
    yawDelta = Obj_GetYawDeltaToObject(param_5, param_6, yawOut);
    if ((double)lbl_803E6F40 == param_4)
    {
        result = 0;
    }
    else
    {
        turnRate = (double)(float)((double)(float)((double)yawOut[0] - param_1) / param_4);
        absRate = turnRate;
        if (turnRate < (double)lbl_803E6F40)
        {
            absRate = -turnRate;
        }
        if ((double)lbl_803E7008 <= absRate)
        {
            if (turnRate < (double)lbl_803E6F40)
            {
                param_2 = -param_2;
            }
            *(float*)(anim + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(anim + 0x280)) +
                *(float*)(anim + 0x280);
            *(float*)(anim + 0x284) = lbl_803E6F40;
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
    int anim;
    double heightDiff;
    float yawOut[7];

    anim = *(int*)(param_5 + 0x5c);
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
            *(float*)(anim + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(anim + 0x280)) +
                *(float*)(anim + 0x280);
            *(float*)(anim + 0x284) = lbl_803E6F40;
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

void GCRobotBlast_free(void)
{
}

void GCRobotBlast_render(void)
{
}

void GCRobotBlast_hitDetect(void)
{
}

void GCRobotBlast_update(void)
{
}

void GCRobotBlast_release(void)
{
}

void GCRobotBlast_initialise(void)
{
}

void DrakorEnergy_func0B_nop(void);

int GCRobotBlast_getExtraSize(void) { return 0x8; }
int GCRobotBlast_getObjectTypeId(void) { return 0x0; }
int drakorenergy_getExtraSize(void);

void GCRobotBlast_init(int obj, s8* p)
{
    
    char* inner = ((GameObject*)obj)->extra;
    ((GCRobotBlastState*)inner)->mode = (s8)p[0x19];
    ((BlastFlags4*)&((GCRobotBlastState*)inner)->flags04)->b80 = 0;
    ((GameObject*)obj)->animEventCallback = (void*)GCRobotBlast_SeqFn;
}

void dbholecontrol1_free(int x);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
