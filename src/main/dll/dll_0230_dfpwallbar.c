/* DLL 0x230 — DFP wall bar / floor bar / torch objects [801FE118-801FEB30) */
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

/*
 * --INFO--
 *
 * Function: FUN_801fd398
 * EN v1.0 Address: 0x801FD398
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x801FD3A4
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* plain forwarder. */

/* fn_X(lbl); lbl = 0; */

/* dll_224_hitDetect: render iff obj->field_0x74 set. */

/* dll_224_update: dispatch GameEvent id based on vtable[0x40](obj->field_0xac). */

/* fn_801FD4A8: decrement extra->[4] by x; return whether it reached 0. */

/* dbegg_setupFromDef: set up dbegg from def fields, dispatch on def->_26 mode byte. */
extern int Obj_SetActiveModelIndex(int obj, int idx);






/* dll_224_init: init extra-data fields from other; set obj->0xaf bit 3. */



/* ==== v1.0 recovered functions (drift additions) ==== */








#pragma opt_common_subs off
#pragma opt_loop_invariants off
#pragma opt_loop_invariants reset
#pragma opt_common_subs reset


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

/* dfplevelcontrol extra block (extraSize 0xC). */

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

/* dfpobjcreator extra block (extraSize 0x1C). */

STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

/* DFP_Torch extra block (extraSize 0x10). */

STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

/* dll_22C (raising platform) extra block (extraSize 0x10). */

STATIC_ASSERT(sizeof(Dll22CState) == 0x10);

/* dbegg extra block: rom-curve walker + egg mode machine. */

STATIC_ASSERT(offsetof(DbEggState, mode) == 0x118);

/* dfpseqpoint extra block (extraSize 0x10). */

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

/* drakorenergy extra block (extraSize 0xC). */

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

/* chuka extra block (extraSize 0xC). */
#include "main/dll/baddie/chuka.h"

typedef struct ChukaPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
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
} ChukaPlacement;

/* GCRobotBlast extra block (extraSize 0x8). */

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

/* dbholecontrol1 extra block (extraSize 0xC). */

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

/*
 * --INFO--
 *
 * Function: FUN_80200558
 * EN v1.0 Address: 0x80200558
 * EN v1.0 Size: 488b
 * EN v1.1 Address: 0x80200D88
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80200558(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;

    iVar1 = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(iVar1 + 0x14) = *(byte*)(iVar1 + 0x14) | 2;
    *(byte*)(iVar1 + 0x15) = *(byte*)(iVar1 + 0x15) | 4;
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
        *(undefined4*)(iVar1 + 0x18) = *(undefined4*)(param_10 + 0x2d0);
        *(undefined2*)(iVar1 + 0x1c) = 0x24;
        *(undefined4*)(iVar1 + 0x2c) = 0;
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                            *(int*)(iVar1 + 0x18), 0x11, param_9, 0x12, param_13, param_14, param_15, param_16);
        FUN_80006824(param_9, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)param_9)->anim.currentMoveProgress)
    {
        *(undefined*)(iVar1 + 0x34) = 1;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200740
 * EN v1.0 Address: 0x80200740
 * EN v1.0 Size: 556b
 * EN v1.1 Address: 0x80200E88
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80200740(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float fVar1;
    uint uVar2;
    int iVar3;
    short* psVar4;
    int iVar5;
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

    iVar5 = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(iVar5 + 0x14) = *(byte*)(iVar5 + 0x14) | 2;
    *(byte*)(iVar5 + 0x15) = *(byte*)(iVar5 + 0x15) & 0xfb;
    fVar1 = lbl_803E6F88;
    *(float*)(param_10 + 0x280) = *(float*)(param_10 + 0x280) / lbl_803E6F88;
    *(float*)(param_10 + 0x284) = *(float*)(param_10 + 0x284) / fVar1;
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
        iVar3 = *(int*)(param_10 + 0x2d0);
        local_24 = *(float*)(iVar3 + 0xc) - ((GameObject*)param_9)->anim.localPosX;
        local_20 = *(float*)(iVar3 + 0x10) - (((GameObject*)param_9)->anim.localPosY + lbl_803E6F94);
        local_1c = *(float*)(iVar3 + 0x14) - ((GameObject*)param_9)->anim.localPosZ;
        dVar6 = FUN_80293900((double)(local_1c * local_1c + local_24 * local_24 + local_20 * local_20));
        if (dVar6 < (double)lbl_803E6F50)
        {
            local_40 = *(undefined4*)(param_10 + 0x2d0);
            psVar4 = *(short**)(iVar5 + 0x24);
            local_48 = 0xe;
            local_44 = 1;
            uVar2 = FUN_80006ab8(psVar4);
            if (uVar2 == 0)
            {
                FUN_80006ac4(psVar4, (uint) & local_48);
            }
            *(undefined*)(iVar5 + 0x34) = 1;
        }
    }
    else
    {
        psVar4 = *(short**)(iVar5 + 0x24);
        local_30 = 9;
        local_2c = 0;
        local_28 = 0x24;
        uVar2 = FUN_80006ab8(psVar4);
        if (uVar2 == 0)
        {
            FUN_80006ac4(psVar4, (uint) & local_30);
        }
        *(undefined*)(iVar5 + 0x34) = 1;
        local_34 = *(undefined4*)(param_10 + 0x2d0);
        psVar4 = *(short**)(iVar5 + 0x24);
        local_3c = 7;
        local_38 = 1;
        uVar2 = FUN_80006ab8(psVar4);
        if (uVar2 == 0)
        {
            FUN_80006ac4(psVar4, (uint) & local_3c);
        }
        *(undefined*)(iVar5 + 0x34) = 1;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80201260
 * EN v1.0 Address: 0x80201260
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x802028CC
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80201260(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    uint uVar2;
    short* psVar3;
    int iVar4;
    undefined4 local_28;
    undefined4 local_24;
    undefined4 local_20;

    iVar4 = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        *(undefined4*)(param_10 + 0x2d0) = 0;
        if (*(int*)(iVar4 + 0x18) != 0)
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                *(int*)(iVar4 + 0x18), 0x11, param_9, 0x10, param_13, param_14, param_15, param_16);
            *(undefined4*)(iVar4 + 0x18) = 0;
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
        local_20 = *(undefined4*)(iVar4 + 0x30);
        local_24 = *(undefined4*)(iVar4 + 0x2c);
        psVar3 = *(short**)(iVar4 + 0x24);
        local_28 = *(undefined4*)(iVar4 + 0x28);
        uVar2 = FUN_80006ab8(psVar3);
        if (uVar2 == 0)
        {
            FUN_80006ac4(psVar3, (uint) & local_28);
        }
        *(undefined4*)(iVar4 + 0x3c) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 0x10;
    *(float*)(param_10 + 0x2a0) = lbl_803E6FD8;
    *(float*)(param_10 + 0x280) = lbl_803E6F40;
    if (*(char*)(param_10 + 0x346) != '\0')
    {
        *(undefined*)(iVar4 + 0x34) = 1;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802014c8
 * EN v1.0 Address: 0x802014C8
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x80202A60
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802014c8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 uVar1;
    int iVar2;

    iVar2 = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar1 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    *(float*)(param_10 + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, uVar1, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    iVar2 = *(int*)(iVar2 + 0x40c);
    *(byte*)(iVar2 + 0x14) = *(byte*)(iVar2 + 0x14) | 2;
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
        *(byte*)(iVar2 + 0x14) = *(byte*)(iVar2 + 0x14) | 1;
    }
    if (*(char*)(param_10 + 0x346) != '\0')
    {
        *(undefined*)(iVar2 + 0x34) = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA09(int obj, int p);

/*
 * --INFO--
 *
 * Function: FUN_80201658
 * EN v1.0 Address: 0x80201658
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80202B5C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80201658(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 uVar1;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar1 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    *(float*)(param_10 + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, uVar1, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802017a0
 * EN v1.0 Address: 0x802017A0
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x80202BF8
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    int iVar3;
    int iVar4;

    iVar3 = *(int*)&((GameObject*)param_9)->extra;
    iVar4 = *(int*)(iVar3 + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar2 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        uVar1 = randomGetRange(0, 1);
        if (uVar1 == 0)
        {
            if (*(char*)(param_10 + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, uVar2, param_13, param_14, param_15, param_16);
                *(undefined*)(param_10 + 0x346) = 0;
            }
        }
        else if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, uVar2, param_13, param_14, param_15, param_16);
            *(undefined*)(param_10 + 0x346) = 0;
        }
        *(undefined*)(param_10 + 0x34d) = 1;
        *(float*)(param_10 + 0x2a0) =
            lbl_803E6FDC +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(iVar3 + 0x406)) - DOUBLE_803e6f78) /
            lbl_803E6FE0;
    }
    *(float*)(param_10 + 0x280) = lbl_803E6F40;
    if (*(char*)(param_10 + 0x346) != '\0')
    {
        *(undefined*)(iVar4 + 0x34) = 1;
    }
    *(byte*)(iVar4 + 0x14) = *(byte*)(iVar4 + 0x14) | 2;
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80202004
 * EN v1.0 Address: 0x80202004
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x802032B0
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_80202130
 * EN v1.0 Address: 0x80202130
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x802033DC
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_80204320
 * EN v1.0 Address: 0x80204320
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x802051FC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204320(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

void fn_80204320(int obj);

/* Trivial 4b 0-arg blr leaves. */

extern u8 lbl_80329514[];

void chuka_render(void)
{
}

/* 8b "li r3, N; blr" returners. */
int GCRobotBlast_getExtraSize(void);
int chuka_SeqFn(void) { return 0x0; }
int chuka_getExtraSize(void) { return 0xc; }
int chuka_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
s16 DBstealerworm_setScale(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */

void chuka_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void chuka_hitDetect(int obj)
{
    int* light;
    int* inner = ((GameObject*)obj)->extra;
    light = (int*)inner[1];
    if (light == NULL) return;
    if ((*(s16*)((char*)light + 6) & 0x40) == 0) return;
    inner[1] = 0;
}

void dbstealerworm_hitDetect(int obj);

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* plain forwarder. */

/* OSReport(string) wrappers. */

/* alpha-flag predicate: returns 7 on fire/clear, 0 on idle */

/* baddie anim update: fires vtable[0x13] when flag set */

/* anim progress accumulator */

/* clear list-actions wrapper: notifies vtable[6] then resets getLActions */

/* timed counter: decrement (p1->b8)->0 by timeDelta, then notify */
extern f32 timeDelta;


void chuka_update(int obj)
{
    extern int*ObjList_GetObjects(int*, int*);
    extern uint GameBit_Get(int);
    extern void Obj_SetActiveModelIndex(int, int);
    extern u8 gChukaModeTable[];
    extern f32 lbl_803E63F8;
    extern f32 lbl_803E63FC;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int blob = *(int*)&((GameObject*)obj)->extra;
    int ch;
    int* base;
    int i;
    int o;
    int h;
    int idx;
    int cnt;
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;

    ch = ((ChukaState*)blob)->linkedObject;
    if ((u32)ch != 0)
    {
        if (*(s16*)(ch + 6) & 0x40)
        {
            ((ChukaState*)blob)->linkedObject = 0;
            return;
        }
    }
    if (*(void**)&((ChukaState*)blob)->linkedObject == NULL)
    {
        base = ObjList_GetObjects(&idx, &cnt);
        for (i = idx; i < cnt; i++)
        {
            o = base[i];
            if (*(s16*)(o + 0x46) == 0x431)
            {
                ((ChukaState*)blob)->linkedObject = o;
                i = cnt;
            }
        }
        if (*(void**)&((ChukaState*)blob)->linkedObject == NULL)
        {
            return;
        }
    }
    ch = ((ChukaState*)blob)->linkedObject;
    (**(void (**)(int, u8*))(*(int*)(*(int*)(ch + 0x68)) + 0x20))(ch, gChukaModeTable);
    if (GameBit_Get(0x5e4) == 0)
    {
        ((ChukaState*)blob)->mode = 0;
    }
    else
    {
        ((ChukaState*)blob)->mode = gChukaModeTable[((ChukaState*)blob)->modeIndex];
    }
    switch (((ChukaState*)blob)->mode)
    {
    case 0:
        if (objAnim->bankIndex != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
        }
        h = ((ChukaPlacement*)data)->unk1C;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        break;
    case 1:
        if (objAnim->bankIndex != 1)
        {
            Obj_SetActiveModelIndex(obj, 1);
        }
        h = ((ChukaPlacement*)data)->unk1C;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0)
        {
            ((GameObject*)obj)->anim.rotZ = 0;
        }
        break;
    case 2:
        if (objAnim->bankIndex != 2)
        {
            Obj_SetActiveModelIndex(obj, 2);
        }
        h = ((ChukaPlacement*)data)->unk1C;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0)
        {
            ((GameObject*)obj)->anim.rotZ = 0;
        }
        break;
    case 3:
        if (objAnim->bankIndex != 2)
        {
            Obj_SetActiveModelIndex(obj, 2);
        }
        h = ((ChukaPlacement*)data)->unk1C;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0x3fff)
        {
            ((GameObject*)obj)->anim.rotZ = 0x7fff;
        }
        break;
    case 4:
        if (objAnim->bankIndex != 1)
        {
            Obj_SetActiveModelIndex(obj, 1);
        }
        h = ((ChukaPlacement*)data)->unk1C;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0x3fff)
        {
            ((GameObject*)obj)->anim.rotZ = 0x7fff;
        }
        break;
    default:
        if (objAnim->bankIndex != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
        }
        h = ((ChukaPlacement*)data)->unk1C;
        if (h != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject*)obj)->anim.rotZ != 0)
        {
            ((GameObject*)obj)->anim.rotZ = 0;
        }
        break;
    }
}

void DFP_Torch_update(int obj);

#include "main/dll/baddie/chuka.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"

extern u8 gChukaModeTable[9];
extern f32 lbl_803E63F8;
extern f32 lbl_803E63FC;

/*
 * --INFO--
 *
 * Function: chuka_init
 * EN v1.0 Address: 0x8020637C
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80206444
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_init(int obj, int params)
{
    ChukaState* state = ((GameObject*)obj)->extra;
    u8* modeTable;

    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (u8*)(params + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = (void*)chuka_SeqFn;
    state->startY = ((GameObject*)obj)->anim.localPosY;
    state->modeIndex = *(u8*)(params + 0x19);

    if (*(s16*)(params + 0x1c) != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale =
            lbl_803E63F8 / ((f32)(s32) * (s16*)(params + 0x1c) / lbl_803E63FC);
    }

    if (*(s16*)(params + 0x1a) != 0)
    {
        ((GameObject*)obj)->anim.rotZ = *(s16*)(params + 0x1a);
    }

    ((GameObject*)obj)->objectFlags |= 0x4000;
    state->linkedObject = 0;

    modeTable = gChukaModeTable;
    {
        int i;
        for (i = 9; i != 0; i--)
        {
            *modeTable = 0;
            modeTable++;
        }
    }
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_free
 * EN v1.0 Address: 0x80206480
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80206590
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/*
 * --INFO--
 *
 * Function: chuka_release
 * EN v1.0 Address: 0x8020646C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_release(void)
{
}

/*
 * --INFO--
 *
 * Function: chuka_initialise
 * EN v1.0 Address: 0x80206470
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_getExtraSize
 * EN v1.0 Address: 0x8020647C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

extern f32 lbl_803E6408;

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
