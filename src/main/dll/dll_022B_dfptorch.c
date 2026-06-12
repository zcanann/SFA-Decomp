/* === moved from main/main.c [801FE118-801FEB30) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/game_object.h"
#include "main/dll/gcrobotblaststate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfp_types.h"
#include "main/dll/db_types.h"
#include "main/dll/anim_internal.h"
#include "main/main.h"
#include "main/objlib.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);


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


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */













/* 8b "li r3, N; blr" returners. */

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma scheduling reset

/* plain forwarder. */

/* fn_X(lbl); lbl = 0; */
#pragma scheduling off
#pragma scheduling reset

/* dll_224_hitDetect: render iff obj->field_0x74 set. */


/* dll_224_update: dispatch GameEvent id based on vtable[0x40](obj->field_0xac). */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


/* fn_801FD4A8: decrement extra->[4] by x; return whether it reached 0. */
#pragma scheduling off
#pragma scheduling reset


/* dbegg_setupFromDef: set up dbegg from def fields, dispatch on def->_26 mode byte. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/* dll_224_init: init extra-data fields from other; set obj->0xaf bit 3. */
#pragma scheduling off
#pragma peephole off

#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma scheduling reset

/* ==== v1.0 recovered functions (drift additions) ==== */

extern f32 sqrtf(f32 x);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_loop_invariants off
#pragma opt_loop_invariants reset
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset

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
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjMsg_SendToObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_8003b818();
extern double FUN_80293900();

extern undefined4 DAT_8032a290;
extern ModgfxInterface** gModgfxInterface;
extern EffectInterface** gPartfxInterface;
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

/* 8b "li r3, N; blr" returners. */
int DFP_Torch_getExtraSize(void) { return 0x10; }
int DFP_Torch_getObjectTypeId(void) { return 0x1; }
int chuka_SeqFn(void);

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */












/* ObjGroup_RemoveObject(x, N) wrappers. */

/* plain forwarder. */

/* OSReport(string) wrappers. */


/* alpha-flag predicate: returns 7 on fire/clear, 0 on idle */

/* baddie anim update: fires vtable[0x13] when flag set */

/* anim progress accumulator */


/* clear list-actions wrapper: notifies vtable[6] then resets getLActions */

/* timed counter: decrement (p1->b8)->0 by timeDelta, then notify */
extern f32 timeDelta;







void DFP_Torch_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dfpobjcreator_init(int obj, s8* def);







extern void fn_80202EF0(int obj, int p2);

#pragma dont_inline on
#pragma dont_inline reset








extern f32 lbl_803E63E4;
extern f32 lbl_803E63E8;
extern f32 lbl_803E63E0;

void DFP_Torch_init(int obj, int param2)
{
    DfpTorchState* state = ((GameObject*)obj)->extra;
    void* res;
    f32 local_18;
    int v;
    *(s16*)obj = (s16)((*(s8*)(param2 + 0x18) & 0x3f) << 10);
    v = *(s16*)(param2 + 0x1a);
    if (v > 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)v / lbl_803E63E4;
    }
    else
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E63E8;
    }
    state->mode = *(u8*)(param2 + 0x19);
    state->gameBit = *(s16*)(param2 + 0x1e);
    local_18 = lbl_803E63E0;
    if (state->mode == 0)
    {
        state->lit = 1;
        res = Resource_Acquire(0x69, 1);
        if (*(s16*)(param2 + 0x1c) == 0)
        {
            (*(void (*)(int, int, void*, int, int, int))(*(int*)(*(int*)res + 4)))(obj, 0, &local_18, 0x10004, -1, 0);
        }
    }
    state->colorIdx = (u8) * (s16*)(param2 + 0x1c);
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
}

void fn_80202EF0(int obj, int p2);

#pragma opt_common_subs off
#pragma dont_inline on
#pragma dont_inline reset
#pragma opt_common_subs reset

#pragma dont_inline on

#pragma dont_inline reset









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





#pragma opt_loop_invariants off
#pragma opt_loop_invariants reset





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
                blob->litTimer = h - (int)timeDelta;
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





/* === moved from main/dll/baddie/chuka.c [8020637C-80206474) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/baddie/chuka.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"


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


/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
