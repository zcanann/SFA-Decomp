/* DLL 0x243 - DBHoleControl1 [801FE118-801FEB30) */
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

typedef struct Dbholecontrol1Placement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    s16 unk18;
    u8 pad1A[0x1C - 0x1A];
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
} Dbholecontrol1Placement;

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

int dbstealerworm_stateHandlerB04(int obj, int p);

int dbstealerworm_stateHandlerB02(int obj, int p);

extern void Obj_RemoveFromUpdateList(int* obj);
extern f32 lbl_803E6390;
extern int gDBStealerWormStateHandlersA[];
extern void DBstealerwo_setFuncPtrs_80203c78(void);
extern int gDBStealerWormStateHandlersB[];
extern int dbstealerworm_stateHandlerA02();
extern int dbstealerworm_stateHandlerA04();
extern int dbstealerworm_stateHandlerA07(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA08(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA0A();
extern int dbstealerworm_stateHandlerA0B(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA0D();
extern int dbstealerworm_stateHandlerA0E();
extern int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerB05();
extern int dbstealerworm_stateHandlerB06();

undefined4
FUN_80200558(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int control;

    control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    *(byte*)(control + 0x15) = *(byte*)(control + 0x15) | 4;
    *(float*)(state + 0x2a0) = lbl_803E6F80;
    if (*(char*)(state + 0x27a) != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, obj, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 0x1f;
    if (*(char*)(state + 0x27a) != '\0')
    {
        *(undefined4*)(control + 0x18) = *(undefined4*)(state + 0x2d0);
        *(undefined2*)(control + 0x1c) = 0x24;
        *(undefined4*)(control + 0x2c) = 0;
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                            *(int*)(control + 0x18), 0x11, obj, 0x12, param_13, param_14, param_15, param_16);
        FUN_80006824(obj, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)obj)->anim.currentMoveProgress)
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
    uint busy;
    int dest;
    short* hits;
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

    control = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    *(byte*)(control + 0x15) = *(byte*)(control + 0x15) & 0xfb;
    divisor = lbl_803E6F88;
    *(float*)(param_10 + 0x280) = *(float*)(param_10 + 0x280) / lbl_803E6F88;
    *(float*)(param_10 + 0x284) = *(float*)(param_10 + 0x284) / divisor;
    *(float*)(param_10 + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 0x1f;
    if ((((GameObject*)param_9)->anim.currentMoveProgress <= lbl_803E6F84) ||
        (((GameObject*)param_9)->anim.localPosY < *(float*)(*(int*)(param_10 + 0x2d0) + 0x10) - lbl_803E6F90))
    {
        dest = *(int*)(param_10 + 0x2d0);
        dx = *(float*)(dest + 0xc) - ((GameObject*)param_9)->anim.localPosX;
        dy = *(float*)(dest + 0x10) - (((GameObject*)param_9)->anim.localPosY + lbl_803E6F94);
        dz = *(float*)(dest + 0x14) - ((GameObject*)param_9)->anim.localPosZ;
        dist = FUN_80293900((double)(dz * dz + dx * dx + dy * dy));
        if (dist < (double)lbl_803E6F50)
        {
            msgWord40 = *(undefined4*)(param_10 + 0x2d0);
            hits = *(short**)(control + 0x24);
            msgWord48 = 0xe;
            msgWord44 = 1;
            busy = FUN_80006ab8(hits);
            if (busy == 0)
            {
                FUN_80006ac4(hits, (uint) & msgWord48);
            }
            *(undefined*)(control + 0x34) = 1;
        }
    }
    else
    {
        hits = *(short**)(control + 0x24);
        msgWord30 = 9;
        msgWord2c = 0;
        msgWord28 = 0x24;
        busy = FUN_80006ab8(hits);
        if (busy == 0)
        {
            FUN_80006ac4(hits, (uint) & msgWord30);
        }
        *(undefined*)(control + 0x34) = 1;
        msgWord34 = *(undefined4*)(param_10 + 0x2d0);
        hits = *(short**)(control + 0x24);
        msgWord3c = 7;
        msgWord38 = 1;
        busy = FUN_80006ab8(hits);
        if (busy == 0)
        {
            FUN_80006ac4(hits, (uint) & msgWord3c);
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
    int hurt;
    uint busy;
    short* hits;
    int control;
    undefined4 msg;
    undefined4 msgArg;
    undefined4 msgTarget;

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
        hurt = FUN_80017a98();
        hurt = (**(code**)(**(int**)(*(int*)(hurt + 200) + 0x68) + 0x44))();
        if (hurt == 0)
        {
            busy = randomGetRange(0, 2);
            FUN_80006824(obj, (ushort) * (undefined4*)(&DAT_8032a290 + busy * 4));
        }
        else
        {
            busy = randomGetRange(3, 4);
            FUN_80006824(obj, (ushort) * (undefined4*)(&DAT_8032a290 + busy * 4));
        }
        msgTarget = *(undefined4*)(control + 0x30);
        msgArg = *(undefined4*)(control + 0x2c);
        hits = *(short**)(control + 0x24);
        msg = *(undefined4*)(control + 0x28);
        busy = FUN_80006ab8(hits);
        if (busy == 0)
        {
            FUN_80006ac4(hits, (uint) & msg);
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
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 animId;
    int control;

    control = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    *(float*)(state + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 10, 0, animId, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 1;
    control = *(int*)(control + 0x40c);
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    if ((*(uint*)(state + 0x314) & 1) != 0)
    {
        *(uint*)(state + 0x314) = *(uint*)(state + 0x314) & ~1;
        *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 1;
    }
    if (*(char*)(state + 0x346) != '\0')
    {
        *(undefined*)(control + 0x34) = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA09(int obj, int p);

undefined4
FUN_80201658(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 animId;

    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    *(float*)(state + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 5, 0, animId, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 1;
    return 0;
}

undefined4
FUN_802017a0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    uint pick;
    undefined4 animId;
    int extra;
    int control;

    extra = *(int*)&((GameObject*)obj)->extra;
    control = *(int*)(extra + 0x40c);
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    if (*(char*)(state + 0x27a) != '\0')
    {
        pick = randomGetRange(0, 1);
        if (pick == 0)
        {
            if (*(char*)(state + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             obj, 7, 0, animId, param_13, param_14, param_15, param_16);
                *(undefined*)(state + 0x346) = 0;
            }
        }
        else if (*(char*)(state + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 6, 0, animId, param_13, param_14, param_15, param_16);
            *(undefined*)(state + 0x346) = 0;
        }
        *(undefined*)(state + 0x34d) = 1;
        *(float*)(state + 0x2a0) =
            lbl_803E6FDC +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e6f78) /
            lbl_803E6FE0;
    }
    *(float*)(state + 0x280) = lbl_803E6F40;
    if (*(char*)(state + 0x346) != '\0')
    {
        *(undefined*)(control + 0x34) = 1;
    }
    *(byte*)(control + 0x14) = *(byte*)(control + 0x14) | 2;
    return 0;
}

undefined4
FUN_80202004(double param_1, double param_2, undefined8 param_3, double param_4, ushort* obj,
             int target)
{
    int yawDelta;
    undefined4 result;
    int control;
    double absDist;
    double signedDist;
    float info[5];

    control = *(int*)(obj + 0x5c);
    yawDelta = Obj_GetYawDeltaToObject(obj, target, info);
    if ((double)lbl_803E6F40 == param_4)
    {
        result = 0;
    }
    else
    {
        signedDist = (double)(float)((double)(float)((double)info[0] - param_1) / param_4);
        absDist = signedDist;
        if (signedDist < (double)lbl_803E6F40)
        {
            absDist = -signedDist;
        }
        if ((double)lbl_803E7008 <= absDist)
        {
            if (signedDist < (double)lbl_803E6F40)
            {
                param_2 = -param_2;
            }
            *(float*)(control + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(control + 0x280)) +
                *(float*)(control + 0x280);
            *(float*)(control + 0x284) = lbl_803E6F40;
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
    int control;
    double absDy;
    float info[7];

    control = *(int*)(obj + 0x5c);
    if ((obj != (ushort*)0x0) && (target != 0))
    {
        yawDelta = Obj_GetYawDeltaToObject(obj, target, info);
        if ((double)lbl_803E6F40 != param_4)
        {
            if ((double)info[0] < param_1)
            {
                absDy = (double)(*(float*)(obj + 8) - *(float*)(target + 0x10));
                if (absDy < (double)lbl_803E6F40)
                {
                    absDy = -absDy;
                }
                if (absDy < (double)lbl_803E7010)
                {
                    return 1;
                }
            }
            *(float*)(control + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(control + 0x280)) +
                *(float*)(control + 0x280);
            *(float*)(control + 0x284) = lbl_803E6F40;
        }
    }
    return 0;
}

int dbstealerworm_stateHandlerA05(int obj, int p);

int dbstealerworm_stateHandlerA03(int obj, int p);

int dbstealerworm_stateHandlerA01(int obj, int p);

void FUN_80204320(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

void fn_80204320(int obj);

void dbholecontrol1_hitDetect(void)
{
}

void dbholecontrol1_release(void)
{
}

void dbholecontrol1_initialise(void)
{
}

void dbholecontrol1_update(int* obj)
{
    extern uint GameBit_Get(int);
    u8* def;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((Dbholecontrol1Placement*)def)->unk1E) != 0)
    {
        Obj_RemoveFromUpdateList(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    }
    else if (GameBit_Get(((Dbholecontrol1Placement*)def)->unk20) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(*(s8*)(def + 0x19), obj, -1);
    }
}

void dbholecontrol1_init(int* obj, u8* params)
{
    extern undefined4 ObjGroup_AddObject(); /* #57 */
    DbHoleControl1State* sub = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, 0x1e);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = (void*)dbholecontrol1_SeqFn;
    sub->gameBitA = *(s16*)(params + 0x1a);
    sub->gameBitB = *(s16*)(params + 0x1c);
}


int dbholecontrol1_getExtraSize(void) { return 0xc; }
int dbholecontrol1_getObjectTypeId(void) { return 0x0; }

void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E6390);
}


void dbholecontrol1_free(int x) { extern undefined8 ObjGroup_RemoveObject(); /* #57 */ ObjGroup_RemoveObject(x, 0x1e); }

int dbstealerworm_stateHandlerB00(int p1, int p2);

int dbstealerworm_stateHandlerB03(int p1, int p2);

int dbstealerworm_stateHandlerB01(int p1, int p2);

int dbstealerworm_stateHandlerA00(int obj, int p2);

int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern void*mapRomListFindItem(int, int, int, int, int);
    extern int Obj_AllocObjectSetup(int, int);
    extern void memcpy(int, void*, int);
    extern void loadObjectAtObject(int, int);
    extern int*ObjGroup_GetObjects(int, int*);
    extern void ObjGroup_RemoveObject(int, int);
    extern void ObjMsg_SendToObjects(int, int, int, int, int);
    extern int lbl_803DDCE0;
    int newObj;
    void* res;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if (GameBit_Get((s32)(s8) * (u8*)(data + 0x19) + 2601) != 0) continue;
            if (Obj_IsLoadingLocked() == 0) continue;
            res = mapRomListFindItem(0x4658A, 0, 0, 0, 0);
            if (res == NULL) continue;
            newObj = Obj_AllocObjectSetup(56, 1337);
            memcpy(newObj, res, 56);
            ((GameObject*)newObj)->anim.rootMotionScale = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)newObj)->anim.localPosX = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)newObj)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
            *(int*)&((GameObject*)newObj)->anim.localPosZ = -1;
            *(s16*)(newObj + 26) = 149;
            loadObjectAtObject(obj, newObj);
            break;
        }
    }

    if (GameBit_Get(((Dbholecontrol1Placement*)data)->unk1E) != 0 || lbl_803DDCE0 != 0)
    {
        int count;
        int* objs = ObjGroup_GetObjects(36, &count);
        ObjMsg_SendToObjects(0, 3, obj, 17, 0);
        while (count-- != 0)
        {
            ObjGroup_RemoveObject(*objs++, 36);
        }
        return 4;
    }
    return 0;
}

int dbstealerworm_func0B(int obj, u8 msg, int* out);

void DBstealerwo_setFuncPtrs_80203c78(void)
{
    gDBStealerWormStateHandlersA[0] = (int)dbstealerworm_stateHandlerA00;
    gDBStealerWormStateHandlersA[1] = (int)dbstealerworm_stateHandlerA01;
    gDBStealerWormStateHandlersA[2] = (int)dbstealerworm_stateHandlerA02;
    gDBStealerWormStateHandlersA[3] = (int)dbstealerworm_stateHandlerA03;
    gDBStealerWormStateHandlersA[4] = (int)dbstealerworm_stateHandlerA04;
    gDBStealerWormStateHandlersA[5] = (int)dbstealerworm_stateHandlerA05;
    gDBStealerWormStateHandlersA[6] = (int)dbstealerworm_stateHandlerA06;
    gDBStealerWormStateHandlersA[7] = (int)dbstealerworm_stateHandlerA07;
    gDBStealerWormStateHandlersA[8] = (int)dbstealerworm_stateHandlerA08;
    gDBStealerWormStateHandlersA[9] = (int)dbstealerworm_stateHandlerA09;
    gDBStealerWormStateHandlersA[10] = (int)dbstealerworm_stateHandlerA0A;
    gDBStealerWormStateHandlersA[11] = (int)dbstealerworm_stateHandlerA0B;
    gDBStealerWormStateHandlersA[12] = (int)dbstealerworm_stateHandlerA0C;
    gDBStealerWormStateHandlersA[13] = (int)dbstealerworm_stateHandlerA0D;
    gDBStealerWormStateHandlersA[14] = (int)dbstealerworm_stateHandlerA0E;
    gDBStealerWormStateHandlersA[15] = (int)dbstealerworm_stateHandlerA0F;
    gDBStealerWormStateHandlersB[0] = (int)dbstealerworm_stateHandlerB00;
    gDBStealerWormStateHandlersB[1] = (int)dbstealerworm_stateHandlerB01;
    gDBStealerWormStateHandlersB[2] = (int)dbstealerworm_stateHandlerB02;
    gDBStealerWormStateHandlersB[3] = (int)dbstealerworm_stateHandlerB03;
    gDBStealerWormStateHandlersB[4] = (int)dbstealerworm_stateHandlerB04;
    gDBStealerWormStateHandlersB[5] = (int)dbstealerworm_stateHandlerB05;
    gDBStealerWormStateHandlersB[6] = (int)dbstealerworm_stateHandlerB06;
}

int dbstealerworm_stateHandlerA04(int obj, int param2);

int dbstealerworm_stateHandlerA0E(int obj, int param2);


int dbstealerworm_stateHandlerA02(int obj, int p2);

int dbstealerworm_stateHandlerA0D(int obj, int p2);

int dbstealerworm_stateHandlerB05(int obj, int p2);

int dbstealerworm_stateHandlerB06(int obj, int p2);

int dbstealerworm_stateHandlerA0A(int obj, int p2);

int dbstealerworm_stateHandlerA0B(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerA07(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerA08(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
