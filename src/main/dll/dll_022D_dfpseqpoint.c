/* DLL 0x22D - DFPSeqPoint [801FE118-801FEB30) */
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
extern void GameBit_Set(int eventId, int value);

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
extern ObjectTriggerInterface** gObjectTriggerInterface;
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
            if (animUpdate->eventIds[i] == 1)
            {
                if ((*gMapEventInterface)->getMode(((GameObject*)obj)->anim.mapEventSlot) == 1)
                {
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 7, 0);
                }
                else if ((*gMapEventInterface)->getMode(((GameObject*)obj)->anim.mapEventSlot) == 2)
                {
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 7, 0);
                }
            }
            break;
        case 0xa:
            if (animUpdate->eventIds[i] == 0x14)
            {
                if (*(u32*)&((DfpseqpointPlacement*)data)->unk14 == 0x49de8)
                {
                    ((DfpFlags7*)&((DfpSeqPointState*)blob)->flags0F)->b80 = 1;
                }
                else
                {
                    if ((*gMapEventInterface)->getMode(((GameObject*)obj)->anim.mapEventSlot) == 1 ||
                        (*gMapEventInterface)->getMode(((GameObject*)obj)->anim.mapEventSlot) == 2)
                    {
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x32), 0);
                        (*gMapEventInterface)->setMode(0x32, 2);
                        warpToMap(0x73, 0);
                    }
                }
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
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern f32 Vec_distance(int, int);
    int player;
    int blob;
    int h;

    player = Obj_GetPlayerObject();
    blob = *(int*)&((GameObject*)obj)->extra;
    if (((u32)((DfpSeqPointState*)blob)->flags0F >> 7 & 1) != 0)
    {
        GameBit_Set(0xef7, 1);
        ((DfpFlags7*)&((DfpSeqPointState*)blob)->flags0F)->b80 = 0;
    }
    h = ((DfpSeqPointState*)blob)->gameBitDone;
    if (h != -1)
    {
        if (((DfpSeqPointState*)blob)->doneLatch != 0)
        {
            if (GameBit_Get(h) != 0)
            {
                return;
            }
            GameBit_Set(((DfpSeqPointState*)blob)->gameBitDone, 1);
            ((DfpSeqPointState*)blob)->doneLatch = 1;
            return;
        }
        if (GameBit_Get(h) != 0)
        {
            ((DfpSeqPointState*)blob)->doneLatch = 1;
            return;
        }
    }
    if (((DfpSeqPointState*)blob)->doneLatch != 0)
    {
        return;
    }
    switch (((DfpSeqPointState*)blob)->triggerMode)
    {
    case 0:
        if (Vec_distance(obj + 0x18, player + 0x18) < ((DfpSeqPointState*)blob)->triggerRadius)
        {
            (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState*)blob)->triggerId,
                                                    (void*)obj, -1);
            ((DfpSeqPointState*)blob)->doneLatch = 1;
        }
        break;
    case 1:
        h = ((DfpSeqPointState*)blob)->gameBitGate;
        if (h != -1 && GameBit_Get(h) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState*)blob)->triggerId,
                                                    (void*)obj, -1);
            ((DfpSeqPointState*)blob)->doneLatch = 1;
        }
        break;
    case 2:
        if (Vec_distance(obj + 0x18, player + 0x18) < ((DfpSeqPointState*)blob)->triggerRadius)
        {
            h = ((DfpSeqPointState*)blob)->gameBitGate;
            if (h != -1 && GameBit_Get(h) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState*)blob)->triggerId,
                                                        (void*)obj, -1);
                ((DfpSeqPointState*)blob)->doneLatch = 1;
            }
        }
        break;
    case 3:
        if (Vec_distance(obj + 0x18, player + 0x18) < ((DfpSeqPointState*)blob)->triggerRadius)
        {
            h = ((DfpSeqPointState*)blob)->gameBitGate;
            if (h != -1 && GameBit_Get(h) == 0)
            {
                (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState*)blob)->triggerId,
                                                        (void*)obj, -1);
                GameBit_Set(((DfpSeqPointState*)blob)->gameBitGate, 1);
                ((DfpSeqPointState*)blob)->doneLatch = 1;
            }
        }
        break;
    case 4:
        h = ((DfpSeqPointState*)blob)->gameBitGate;
        if (h != -1 && GameBit_Get(h) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState*)blob)->triggerId,
                                                    (void*)obj, -1);
            GameBit_Set(((DfpSeqPointState*)blob)->gameBitGate, 1);
            ((DfpSeqPointState*)blob)->doneLatch = 1;
        }
        break;
    case 5:
        h = ((DfpSeqPointState*)blob)->gameBitGate;
        if (h != -1 && GameBit_Get(h) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState*)blob)->triggerId,
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
