/* === moved from main/dll/DR/hightop.c [8019AE3C-8019B1D8) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "main/game_object.h"
#include "main/dll/wormspitbyte_struct.h"
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/dll/babycloudrunnerflags_struct.h"
#include "main/dll/gcrobotlightbeastate_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/dll/rom_curve_interface.h"









/*
 * --INFO--
 *
 * Function: objInterpretSeq
 * EN v1.0 Address: 0x801993B0
 * EN v1.0 Size: 6644b
 * EN v1.1 Address: 0x8019992C
 * EN v1.1 Size: 3936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8019ae30
 * EN v1.0 Address: 0x8019AE30
 * EN v1.0 Size: 2172b
 * EN v1.1 Address: 0x8019A92C
 * EN v1.1 Size: 1268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off











/* 8b "li r3, N; blr" returners. */

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */


/* call(x, N) wrappers. */

int cfguardian_setScale(int* obj)
{
    return (*(u8*)(*(int*)&((GameObject*)obj)->extra + 0xa9b) & 0x2) == 0;
}

extern void Sfx_PlayFromObject(int obj, int sfxId);

void fn_8019AE3C(int p1, int p2, s16* p3)
{
    u8 v;
    int i;

    v = 0;
    for (i = 0; i < *(s8*)(p2 + 0x1b); i++)
    {
        switch (*(s8*)(p2 + i + 0x13))
        {
        case 0:
            if (p3 != NULL)
            {
                Sfx_PlayFromObject(p1, (u16)p3[0]);
            }
            break;
        case 7:
            if (p3 != NULL)
            {
                Sfx_PlayFromObject(p1, (u16)p3[1]);
            }
            break;
        case 1:
            v = 1;
            break;
        case 2:
            v = 2;
            break;
        case 3:
            v = 3;
            break;
        case 4:
            v = 4;
            break;
        case 9:
            Sfx_PlayFromObject(p1, 0xe1);
            break;
        }
    }
    if (v != 0 && p3 != NULL)
    {
        Sfx_PlayFromObject(p1, (u16)p3[2]);
    }
}

/* cloudprisoncontrol map-event tables (recovered layout; kept raw int[] - the
 * struct-field form flips MWCC's variable-index/walker addressing, banked).
 * lbl_803AC7D8: registered-target list, 8-byte entries (count lbl_803DDB09):
 *   s32 target @0; s16 data @4; u8 unk6 @6 (zeroed on add); u8 pad @7.
 * lbl_803AC878: deferred-message queue, 12-byte entries (count lbl_803DDB08):
 *   s32 message @0; s32 target @4; s32 data @8. */


extern int* findRomCurvePointNearObject(int* obj, int p2, int* outVec, int p4);
extern int fn_8019B1D8(int* obj, int* target, f32 speed, int p4);
extern int Curve_AdvanceAlongPath(int p1);
extern s16 getAngle(f32 a, f32 b);
extern f32 lbl_803E4110;
extern f32 lbl_803E4120;

typedef struct
{
    s16 angle;
    s16 pad[5];
    f32 x;
    f32 y;
    f32 z;
} RomCurveTarget;

int fn_8019AF64(int obj, int p2, f32 t, int p3, int p4)
{
    extern int hitDetectFn_800658a4(f32 x, f32 y, f32 z, int obj, f32* out, int p6); /* #57 */
    int ret;
    int moved;
    u8 sel;
    int pt;
    s16 v;
    int cmd[2];
    RomCurveTarget tgt;
    f32 ground;

    moved = 1;
    ret = 0;
    ground = lbl_803E4110;
    if (((GameObject*)obj)->unkF4 == -1)
    {
        return 1;
    }
    if (((GameObject*)obj)->unkF4 == 0)
    {
        sel = p3;
        pt = (int)findRomCurvePointNearObject((int*)obj, sel, 0, 2);
        tgt.x = *(f32*)(pt + 8);
        tgt.y = *(f32*)(pt + 0xc);
        tgt.z = *(f32*)(pt + 0x10);
        tgt.angle = *(s8*)(pt + 0x2c) << 8;
        if (fn_8019B1D8((int*)obj, (int*)&tgt.angle, t, p4) != 0)
        {
            cmd[0] = 0x19;
            cmd[1] = 0x15;
            (*gRomCurveInterface)->initCurve((void*)p2, (void*)obj, lbl_803E4120, cmd, sel);
            ((GameObject*)obj)->unkF4 = 1;
            moved = 1;
        }
    }
    else
    {
        ret = 0;
        if (Curve_AdvanceAlongPath(p2) != 0 || *(int*)(p2 + 0x10) != 0)
        {
            ret = (*gRomCurveInterface)->goNextPoint((void*)p2);
        }
        ((GameObject*)obj)->anim.localPosX = *(f32*)(p2 + 0x68);
        ((GameObject*)obj)->anim.localPosY = *(f32*)(p2 + 0x6c);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(p2 + 0x70);
        if (ret != 0)
        {
            ((GameObject*)obj)->unkF4 = -1;
        }
        if (hitDetectFn_800658a4(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, obj, &ground, 0) == 0)
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - ground;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(obj, t, (float*)p4);
    if (moved != 0)
    {
        v = (s16)(getAngle(((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX,
                           ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ) + 0x8000);
        v = v - (u16) * (s16*)obj;
        if (v > 0x8000)
        {
            v -= 0xffff;
        }
        if (v < -0x8000)
        {
            v += 0xffff;
        }
        *(s16*)obj = *(s16*)obj + (v >> 3);
    }
    if (((GameObject*)obj)->anim.currentMove != 0x1a)
    {
        ObjAnim_SetCurrentMove(obj, 0x1a, lbl_803E4110, 0);
    }
    return ret;
}
#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset

/*
 * CFGuardian (DLL 0x148) - CloudRunner Fortress guardian (head fragment).
 * Re-split (descriptor forensics, docs/boundary_audit.md): this unit holds
 * [8019B1D8-8019C784) = dll 0x148's helpers + descriptor fns, carved from
 * the front of the 12-DLL container sandwormBoss.c. NOTE: 0x148's TU truly
 * starts inside DR/hightop.c (its slot-10 callback is at 0x8019AF4C); the
 * hightop|here boundary at 0x8019B1D8 is a remaining documented cut.
 * Skeleton-copy carve: non-owned defs collapsed to prototypes in place.
 */
#include "main/dll/cfguardian_state.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objseq.h"

extern undefined4 getLActions();
extern undefined8 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern bool ObjTrigger_UpdateIdBlockFlag(int obj);
extern int ObjTrigger_IsSet();
extern undefined4 objAnimFn_80038f38();
extern void objRenderFn_8003b8f4(f32);
extern undefined4 FUN_8006f7a0();
extern int FUN_8007f924();
extern undefined4 FUN_800e8630();
extern int FUN_801149b8();
extern undefined4 dll_2E_func03();
extern double FUN_80293900();
extern undefined4 FUN_80294d40();

extern undefined4 DAT_802c2a58;
extern undefined4 DAT_802c2a5c;
extern undefined4 DAT_802c2a60;
extern undefined4 DAT_802c2a64;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f64 DOUBLE_803e4db0;
extern f32 lbl_803DC074;
extern f32 gBoneParticleEffectInterface;
extern f32 lbl_803E4DA8;
extern f32 lbl_803E4DBC;
extern f32 lbl_803E4DC0;
extern f32 lbl_803E4EB0;
extern f32 lbl_803E4EC4;
extern f32 lbl_803E4EC8;
extern f32 lbl_803E4ECC;

/*
 * --INFO--
 *
 * Function: FUN_8019b1d8
 * EN v1.0 Address: 0x8019B1D8
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x8019B3B8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_8019b2e0
 * EN v1.0 Address: 0x8019B2E0
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x8019B754
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b2e0(double param_1, short* param_2, short* param_3, float* param_4, undefined4 param_5,
             undefined4 param_6, undefined4 param_7, undefined4 param_8, undefined4 param_9)
{
    int iVar1;
    short sVar2;
    undefined4 uVar3;
    double dVar4;
    double dVar5;
    double dVar6;
    undefined8 in_f5;
    undefined8 in_f6;
    undefined8 in_f7;
    undefined8 in_f8;
    float local_58;
    float local_54;
    float local_50[2];
    undefined4 local_48;
    uint uStack_44;
    undefined4 local_40;
    uint uStack_3c;
    longlong local_38;

    if (param_3 == (short*)0x0)
    {
        uVar3 = 0;
    }
    else
    {
        local_50[0] = *(float*)(param_3 + 6) - *(float*)(param_2 + 6);
        dVar6 = (double)local_50[0];
        local_54 = *(float*)(param_3 + 8) - *(float*)(param_2 + 8);
        local_58 = *(float*)(param_3 + 10) - *(float*)(param_2 + 10);
        dVar4 = FUN_80293900((double)(local_58 * local_58 + (float)(dVar6 * dVar6) + local_54 * local_54
        ));
        if ((double)(float)((double)lbl_803E4DBC * param_1) <= dVar4)
        {
            FUN_8006f7a0(local_50, &local_54, &local_58);
            *(float*)(param_2 + 0x12) = lbl_803DC074 * (float)((double)local_50[0] * param_1);
            *(float*)(param_2 + 0x14) = lbl_803DC074 * (float)((double)local_54 * param_1);
            *(float*)(param_2 + 0x16) = lbl_803DC074 * (float)((double)local_58 * param_1);
            sVar2 = (*param_3 + -0x8000) - *param_2;
            if (0x8000 < sVar2)
            {
                sVar2 = sVar2 + 1;
            }
            if (sVar2 < -0x8000)
            {
                sVar2 = sVar2 + -1;
            }
            uStack_44 = (int)*param_2 ^ 0x80000000;
            local_48 = 0x43300000;
            uStack_3c = (int)sVar2 ^ 0x80000000;
            local_40 = 0x43300000;
            iVar1 = (int)
            ((f32)(s32)
            uStack_44 +
                (float)((double)((lbl_803E4DC0 +
                    (float)((double)CONCAT44(0x43300000, uStack_3c) - DOUBLE_803e4db0
                    )) * (float)(param_1 * (double)lbl_803DC074)) / dVar4)
            )
            ;
            local_38 = (longlong)iVar1;
            *param_2 = (short)iVar1;
            dVar4 = (double)*(float*)(param_2 + 0x14);
            dVar5 = (double)*(float*)(param_2 + 0x16);
            FUN_80017a88((double)*(float*)(param_2 + 0x12), dVar4, dVar5, (int)param_2);
            if (param_2[0x50] != 0x1a)
            {
                FUN_800305f8((double)lbl_803E4DA8, dVar4, dVar5, dVar6, in_f5, in_f6, in_f7, in_f8, param_2, 0x1a, 0
                             , param_5, param_6, param_7, param_8, param_9);
            }
            FUN_8002f6ac(param_1, (int)param_2, param_4);
            uVar3 = 0;
        }
        else
        {
            uVar3 = 1;
        }
    }
    return uVar3;
}


/*
 * --INFO--
 *
 * Function: FUN_8019b650
 * EN v1.0 Address: 0x8019B650
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8019BA44
 * EN v1.1 Size: 3800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b650(undefined8 param_1, double param_2, double param_3, double param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* param_9,
             undefined4 param_10, undefined4 param_11, float* param_12, int param_13, undefined4 param_14
             , undefined4 param_15, undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b658
 * EN v1.0 Address: 0x8019B658
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8019C91C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b658(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , int param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 uVar1;
    int iVar2;
    float* pfVar3;
    undefined4* puVar4;
    undefined4 local_28;
    undefined4 local_24;
    undefined4 local_20;
    undefined4 local_1c;

    pfVar3 = ((GameObject*)param_9)->extra;
    local_28 = DAT_802c2a58;
    local_24 = DAT_802c2a5c;
    local_20 = DAT_802c2a60;
    local_1c = DAT_802c2a64;
    if (((GameObject*)param_9)->seqIndex < 0)
    {
        FUN_800e8630(param_9);
        uVar1 = 0;
    }
    else
    {
        if (*(char*)(pfVar3 + 0x2a0) == '\x06')
        {
            puVar4 = &local_20;
        }
        else
        {
            puVar4 = &local_28;
        }
        iVar2 = FUN_8007f924(param_11);
        if ((iVar2 == 0x283) ||
            (iVar2 = FUN_801149b8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9
                                  , param_11, pfVar3, (short)*puVar4, (short)puVar4[1], param_14, param_15,
                                  param_16), iVar2 == 0))
        {
            if (*(char*)(param_11 + 0x80) == '\x02')
            {
                iVar2 = FUN_80017a98();
                FUN_80294d40(iVar2, 10);
            }
            uVar1 = 0;
        }
        else
        {
            uVar1 = 1;
        }
    }
    return uVar1;
}


/*
 * --INFO--
 *
 * Function: FUN_8019c318
 * EN v1.0 Address: 0x8019C318
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x8019DAF4
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019c318(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , undefined4 param_10, int param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    uint uVar2;
    short* psVar3;
    uint local_28;
    uint local_24;
    uint local_20[4];

    psVar3 = ((GameObject*)param_9)->extra;
    local_28 = 0;
    while (iVar1 = ObjMsg_Pop(param_9, &local_24, local_20, &local_28), iVar1 != 0)
    {
        if (local_24 == 0x110001)
        {
            if ((*psVar3 == 0x54) && (0xaf < *(short*)(param_11 + 0x58)))
            {
                ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_20[0],
                                    0x110001, param_9, 0, param_13, param_14, param_15, param_16);
            }
        }
        else if ((int)local_24 < 0x110001)
        {
            if (local_24 == 0xa0005)
            {
                param_1 = FUN_80017698((int)*psVar3, 1);
            }
        }
        else if (local_24 == 0x110003)
        {
            if ((*psVar3 == 0x56) && (0xaf < *(short*)(param_11 + 0x58)))
            {
                ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_20[0],
                                    0x110003, param_9, 0, param_13, param_14, param_15, param_16);
            }
        }
        else if ((((int)local_24 < 0x110003) && (*psVar3 == 0x55)) &&
            (0xaf < *(short*)(param_11 + 0x58)))
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, local_20[0],
                                0x110002, param_9, 0, param_13, param_14, param_15, param_16);
        }
    }
    for (iVar1 = 0; iVar1 < (int)(uint) * (byte*)(param_11 + 0x8b); iVar1 = iVar1 + 1)
    {
        if (((*(char*)(param_11 + iVar1 + 0x81) == '\x01') && (uVar2 = FUN_80017690(0x54), uVar2 != 0))
            && ((uVar2 = FUN_80017690(0x55), uVar2 != 0 && (uVar2 = FUN_80017690(0x56), uVar2 != 0))))
        {
            FUN_80017698(0x4e0, 1);
        }
    }
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_8019d238
 * EN v1.0 Address: 0x8019D238
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x8019E970
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019d238(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    double dVar2;

    iVar1 = *(int*)&((GameObject*)param_9)->extra;
    if ((((GameObject*)param_9)->anim.currentMove != 5) && (((GameObject*)param_9)->anim.currentMove != 0xd))
    {
        FUN_800305f8((double)((GameObject*)param_9)->anim.currentMoveProgress, param_2, param_3, param_4, param_5,
                     param_6, param_7,
                     param_8, param_9, 0xd, 0, param_12, param_13, param_14, param_15, param_16);
    }
    if ((((GameObject*)param_9)->anim.currentMove == 5) && (lbl_803E4EC4 < ((GameObject*)param_9)->anim.velocityY))
    {
        FUN_800305f8((double)((GameObject*)param_9)->anim.currentMoveProgress, param_2, param_3, param_4, param_5,
                     param_6, param_7,
                     param_8, param_9, 0xd, 0, param_12, param_13, param_14, param_15, param_16);
    }
    if ((((GameObject*)param_9)->anim.currentMove == 0xd) && (((GameObject*)param_9)->anim.velocityY < lbl_803E4EB0))
    {
        FUN_800305f8((double)((GameObject*)param_9)->anim.currentMoveProgress, param_2, param_3, param_4, param_5,
                     param_6, param_7,
                     param_8, param_9, 5, 0, param_12, param_13, param_14, param_15, param_16);
    }
    dVar2 = (double)((((GameObject*)param_9)->anim.velocityY * gBoneParticleEffectInterface + lbl_803E4EC8) * lbl_803E4ECC);
    if (dVar2 < (double)lbl_803E4EB0)
    {
        dVar2 = (double)lbl_803E4EB0;
    }
    if ((double)lbl_803E4ECC < dVar2)
    {
        dVar2 = (double)lbl_803E4ECC;
    }
    if (((GameObject*)param_9)->anim.currentMove == 0xd)
    {
        if (((GameObject*)param_9)->anim.currentMoveProgress <= lbl_803E4ECC)
        {
            *(byte*)(iVar1 + 0x244) = *(byte*)(iVar1 + 0x244) & 0xbf;
        }
        else if ((*(byte*)(iVar1 + 0x244) >> 6 & 1) == 0)
        {
            FUN_80006824(param_9, SFXand_spitout);
            *(byte*)(iVar1 + 0x244) = *(byte*)(iVar1 + 0x244) & 0xbf | 0x40;
        }
    }
    FUN_8002fc3c(dVar2, (double)lbl_803DC074);
    return 1;
}


/*
 * --INFO--
 *
 * Function: babycloudrunner_getObjectTypeId
 * EN v1.0 Address: 0x8019EBBC
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801A0A24
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void babycloudrunner_init_OLD_v1_1(int obj);

extern uint GameBit_Get(int eventId);
extern int Obj_RemoveFromUpdateList(int* obj);



/* Per-object extra state for the baby CloudRunner
 * (babycloudrunner_getExtraSize == 0x248). */
typedef struct BabyCloudRunnerState
{
    f32 unk00;
    u8 pad04[0x38]; /* 0x18: position used for the sandworm handoff */
    u8 lookBlock[0x30]; /* 0x3c: fn_8003ADC4 head-track block */
    u8 audioBlock[0x3c]; /* 0x6c: objAudioFn block */
    f32 animSpeed;
    f32 scale; /* 0xac: copied to the linked object's scale */
    int unkB0;
    int unkB4;
    int unkB8;
    int unkBC;
    int turnLatch; /* 0xc0: sandworm_turnTowardTargetAnim turn/idle move latch */
    int behaviourState; /* 0xc4: def[0x1c]; SeqFn 0..0xb dispatch */
    u8 padC8[4];
    int unkCC;
    s16 roostYaw; /* 0xd0: heading captured at init */
    u8 padD2[0x42];
    void* linkedObj; /* 0x114 */
    u8 pad118[0xc];
    u8 curveWalker[0x108]; /* 0x124: rom-curve follow block */
    u8 flags22C; /* 1 = alive/active */
    u8 pad22D[3];
    int runnerState; /* 0x230: 0 curve-seek, 1 follow, 2 chased, 3 freed */
    int runnerIndex; /* 0x234: gamebit base index, -1 keyed off */
    f32 countdownTimer; /* 0x238 */
    f32 curveSpeed; /* 0x23c */
    void* mutterSfxTable; /* 0x240 */
    u8 spitFlags; /* 0x244: BabyCloudrunnerFlags / WormSpitByte overlay */
    u8 pad245[3];
} BabyCloudRunnerState;

STATIC_ASSERT(sizeof(BabyCloudRunnerState) == 0x248);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: babycloudrunner_render
 * EN v1.0 Address: 0x8019EC00
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801A0A70
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma peephole reset


/*
 * --INFO--
 *
 * Function: FUN_8019f1dc
 * EN v1.0 Address: 0x8019F1DC
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x801A1190
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
void cfguardian_release(void)
{
}

void cfguardian_initialise(void)
{
}

typedef struct
{
    int a;
    int b;
    s16 c;
} GuardianVec;

extern GuardianVec lbl_802C22C0;
extern GuardianVec lbl_802C22CC;
extern u8 lbl_8032284C[];
extern void dll_2E_func0A(int a, int* obj);
extern void dll_2E_func05(int* obj, u8* sub, int c, int d, int e);
extern void dll_2E_func08(u8* sub, int b, int c);
extern void dll_2E_func09(u8* sub, void* a, void* b, int c);
extern void objSeqInitFn_80080078(u8* p, int n);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

#pragma scheduling off
#pragma peephole off
void cfguardian_init(int* obj, u8* params)
{
    CfGuardianState * sub;
    GuardianVec stk1;
    GuardianVec stk2;

    sub = ((GameObject*)obj)->extra;
    stk1 = lbl_802C22C0;
    stk2 = lbl_802C22CC;
    if (sub == NULL) return;
    ObjMsg_AllocQueue(obj, 4);
    sub->questState = (u8)GameBit_Get(0x4b);
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = (void*)cfguardian_SeqFn;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    sub->landingPhase = 0;
    sub->moveSpeed = lbl_803E4110;
    sub->unkA90 = 6;
    sub->flagsA9B = 0;
    sub->flags611 = (u8)(sub->flags611 | 0x28);
    sub->chatterState = 1;
    sub->chatterAlt = 0;
    sub->chatterPick = 0;
    if (GameBit_Get(0x57) != 0)
    {
        sub->questState = 4;
        if ((s8)params[0x19] == 0)
        {
            ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | 0x4000);
            Obj_RemoveFromUpdateList(obj);
        }
    }
    else if (GameBit_Get(0x60) != 0 && (s8)params[0x19] == 0)
    {
        sub->questState = 4;
        dll_2E_func0A(8, obj);
    }
    ObjHits_EnableObject(obj);
    dll_2E_func05(obj, (u8*)sub, -0x2000, 0x2800, 4);
    dll_2E_func08((u8*)sub, 0x12c, 0x64);
    dll_2E_func09((u8*)sub, &stk2, &stk1, 4);
    objSeqInitFn_80080078(lbl_8032284C, 0xf);
    sub->flags611 = (u8)(sub->flags611 | 0x2);
}
#pragma peephole reset
#pragma scheduling reset

typedef struct
{
    int a, b, c, d;
} GuardianMsg;

extern GuardianMsg lbl_802C22D8;
extern int dll_2E_func07(int* obj, ObjAnimUpdateState* animUpdate, u8* sub, int x, int y);
extern int animatedObjGetSeqId(int* p);
extern void saveGame_saveObjectPos(int obj);
extern void* Obj_GetPlayerObject(void);
extern void playerAddRemoveMagic(void* player, int n);

/* EN v1.0 0x8019C3A0  size: 252b  cfguardian_SeqFn: guardian message handler.
 * Persists position on a negative cue, otherwise picks the active/idle
 * heading pair and routes a move request; on the magic-grant message it
 * tops the player back up. Returns 1 if the move was consumed. */
#pragma scheduling off
#pragma peephole off
int cfguardian_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* sel;
    GuardianMsg stk;
    CfGuardianState * sub = ((GameObject*)obj)->extra;
    stk = lbl_802C22D8;
    if (((GameObject*)obj)->seqIndex < 0)
    {
        saveGame_saveObjectPos((int)obj);
        return 0;
    }
    if (sub->questState != 6)
    {
        sel = &stk.a;
    }
    else
    {
        sel = &stk.c;
    }
    if (animatedObjGetSeqId((int*)animUpdate) != 0x283)
    {
        if (dll_2E_func07(obj, animUpdate, (u8*)sub, (s16)sel[0], (s16)sel[1]) != 0)
        {
            return 1;
        }
    }
    if (animUpdate->triggerCommand == 2)
    {
        playerAddRemoveMagic(Obj_GetPlayerObject(), 0xa);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern f32 timeDelta;

/* EN v1.0 0x8019E568  size: 352b  sandworm_turnTowardTargetAnim: turn toward the target by
 * a fraction of the yaw delta; when roughly aligned play/advance the idle
 * move, otherwise start or speed-scale the turn move by the delta. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void sandworm_turnTowardTargetAnim(int* a, int* b, u8* c, int d);
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset


/* EN v1.0 0x801A0614  size: 368b  cfprisoncage_SeqFn: drain the object's message
 * queue (re-arming its gamebit on the keyed message), then sync the
 * lit/active state from gamebit 0x44 and notify on completion. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern void objAudioFn_800393f8(int obj, void* p, int a, int b, int c, int d);

/* EN v1.0 0x8019E6C8  size: 316b  babycloudrunner_func0B: when the player
 * gets within the trigger radius and the runner is in state 3, fire its
 * burst (notify, bump the counter, set the gamebit); otherwise just play
 * the idle audio cue. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset









/* Per-object extra state for the CloudRunner main crystal
 * (cfmaincrystal_getExtraSize == 0x160). */


STATIC_ASSERT(sizeof(CfMainCrystalState) == 0x160);

/* Per-object extra state for the CloudRunner power base
 * (cfpowerbase_getExtraSize == 0x6). */


STATIC_ASSERT(sizeof(CfPowerBaseState) == 0x6);

/* Per-object extra state for the CloudRunner prison guard
 * (cfprisonguard_getExtraSize == 0x3c). */


STATIC_ASSERT(sizeof(CfPrisonGuardState) == 0x3c);

/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */


STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */


STATIC_ASSERT(sizeof(GcRobotLightBeaState) == 0xc);

/* spiritdoorspirit_getExtraSize == 0x1. */










typedef struct CfguardianState
{
    u8 pad0[0x68C - 0x0];
    void* unk68C;
    u8 pad690[0xA9C - 0x690];
} CfguardianState;














/* EN v1.0 0x8019D8B4  size: 308b  cfpowerbase_init: seed header and the
 * sub's type from spawn params, map the type id (0x54..0x56) to a model
 * and gamebit, then gate the active/lit state bits on those gamebits. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


/* EN v1.0 0x8019D77C  size: 312b  cfpowerbase_update: track its gamebit's
 * lit state, fire the queued state-change trigger, and when the base is
 * powered and its UI condition clears, mark it done and notify. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset










/* EN v1.0 0x8019FBD0  size: 172b  cfprisonguard_init: set up the guard's
 * substate (update fn cfprisonguard_SeqFn, message queue), seed its header from
 * the spawn params, and apply the alarm-active gating bits. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset




extern u8 framesThisStep;

/* EN v1.0 0x8019FEDC  size: 536b  cfprisonuncle_update: while not captured,
 * drain pending messages, re-acquire the keyed target object, then either
 * track/animate toward the player (firing the alert trigger) or, once
 * captured, raise the done flag and notify. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset




/* EN v1.0 0x801A01E8  size: 296b  gcrobotlightbea_hitDetect: clear the hit
 * flag, then re-set it only if the priority hit is the (undisguised) player
 * and lands inside the beacon's bounding box. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset







#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset



/* 8b "li r3, N; blr" returners. */
int cfguardian_getExtraSize(void) { return 0xa9c; }
int cfguardian_getObjectTypeId(void) { return 0x41; }
int windlift_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
#pragma peephole off



#pragma peephole reset


/* EN v1.0 0x8019F93C  size: 188b  cfprisonguard_render: render the guard
 * model when visible, ramp its alarm timer at sub->_30 each frame, and
 * once it crosses the threshold spawn a one-shot particle. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma scheduling reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
#pragma peephole reset

/* chained byte bit-extract. */




/* state-transition: kicks player into mode 2 when sandworm not yet eaten. */
#pragma peephole off
int fn_8019FC84(int* obj, int unused, ObjAnimUpdateState* animUpdate);
#pragma peephole reset

/* GameBit-gated byte write. */
#pragma scheduling off
#pragma scheduling reset

/* plain forwarder. */
extern int waterSpellStone1Fn_8019b4c8();
void cfguardian_update(void) { waterSpellStone1Fn_8019b4c8(); }

/* Drift-recovery: add new fns with v1.0 names. */
extern f32 lbl_803E42B8;
extern f32 lbl_803E4130;
/* ObjLink_DetachChild already declared above as undefined4 ObjLink_DetachChild() */
extern void dll_2E_func06(int* a, int* b, int c);
/* ObjMsg_AllocQueue already declared as undefined */

#pragma scheduling off
#pragma peephole off
















void cfguardian_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* state = ((GameObject*)obj)->extra;
    if ((s32)visible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E4130);
        dll_2E_func06(obj, state, 0);
    }
}

void cfprisoncage_hitDetect(int* obj);




void cfguardian_free(int* obj, int p2)
{
    char* state = ((GameObject*)obj)->extra;
    if (p2 == 0)
    {
        int i;
        for (i = 0; i < 6; i++)
        {
            int* sub = *(int**)&((CfguardianState*)state)->unk68C;
            if (sub != NULL)
            {
                Obj_FreeObject(sub);
            }
            state += 4;
        }
    }
}


void cfprisonuncle_init(int* obj);

#pragma peephole reset
#pragma scheduling reset

/* copy 3 floats within same struct */
void cfguardian_hitDetect(int* obj)
{
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
}

#pragma scheduling off
#pragma dont_inline on
int* findRomCurvePointNearObject(int* obj, int p2, int* outVec, int p4)
{
    int* result = NULL;
    int local[2];
    int found;

    if (p4 == 1)
    {
        local[0] = 0;
        local[1] = 0;
    }
    else
    {
        local[0] = 25;
        local[1] = 21;
    }

    found = (*gRomCurveInterface)->find(
        local, 2, p2,
        ((GameObject*)obj)->anim.localPosX,
        ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ);

    if (found > -1)
    {
        result = (int*)(*gRomCurveInterface)->getById(found);
        if (outVec != NULL)
        {
            *(f32*)((char*)outVec + 0) = *(f32*)((char*)result + 8);
            *(f32*)((char*)outVec + 4) = *(f32*)((char*)result + 12);
            *(f32*)((char*)outVec + 8) = *(f32*)((char*)result + 16);
        }
    }
    return result;
}
#pragma dont_inline reset
#pragma scheduling reset

extern void fn_8019D9F0(int* obj);
#pragma peephole off
#pragma scheduling off
#pragma scheduling reset
#pragma peephole reset

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






/* EN v1.0 0x8019E3F4  size: 372b  fn_8019E3F4: pick the burrow/surface move
 * from the vertical speed, clamp the playback rate, latch the spit SFX
 * while surfacing fast, and advance the current move. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset


/* EN v1.0 0x8019FCF4  size: 484b  cfprisonuncle_render: render the uncle and/or
 * his held model depending on the rescue gamebits, opacity and visibility;
 * when path-following, snap the held model to the path point first. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern f32 sqrtf(f32 x);
extern void normalize(f32 * x, f32 * y, f32 * z);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern f32 lbl_803E4124;
extern f32 lbl_803E4128;

/* EN v1.0 0x8019B1D8  size: 544b  fn_8019B1D8: steer the object toward the
 * target: scale its velocity along the normalized delta, blend the yaw by
 * speed over distance, move it and keep the chase move playing. Returns 1
 * when already within the closing threshold. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int fn_8019B1D8(int* obj, int* target, f32 speed, int p4)
{
    f32 dist;
    f32 dx;
    f32 dy;
    f32 dz;
    s16 d;
    if (target == NULL)
    {
        return 0;
    }
    dx = ((GameObject*)target)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    dy = ((GameObject*)target)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    dz = ((GameObject*)target)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
    dist = sqrtf(dz * dz + (dx * dx + dy * dy));
    if (dist < lbl_803E4124 * speed)
    {
        return 1;
    }
    normalize(&dx, &dy, &dz);
    ((GameObject*)obj)->anim.velocityX = timeDelta * (dx * speed);
    ((GameObject*)obj)->anim.velocityY = timeDelta * (dy * speed);
    ((GameObject*)obj)->anim.velocityZ = timeDelta * (dz * speed);
    d = (*(s16*)target + 0x8000) - (u16) * (s16*)obj;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    *(s16*)obj = (f32) * (s16*)obj + ((lbl_803E4128 + (f32)d) * (speed * timeDelta)) / dist;
    objMove((int)obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    if (((GameObject*)obj)->anim.currentMove != 0x1a)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
    }
    ((int(*)(int*, f32, int))ObjAnim_SampleRootCurvePhase)(obj, speed, p4);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern int seqStreamLookupFn_8007fff8(void* table, int count, int key);



/* EN v1.0 0x8019D2AC  size: 708b  windlift_init: look up the lift's sequence
 * timings, scale its rise height from the def byte, arm it from the
 * gamebits and clear all 14 rider slots. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset




/* EN v1.0 0x8019E81C  size: 920b  babycloudrunner_SeqFn: range-check the
 * runner against the player and its trigger radii, chirp for queued cues,
 * then steer toward the player (or Tricky) per the current behaviour state. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset



/* EN v1.0 0x8019F540  size: 1000b  cfprisonguard_SeqFn: drive the guard state
 * machine - ramp/reset the alarm on cues, bail when captured or freed, watch
 * the player distance/water impacts and chase or stand down, with idle digging
 * SFX and queued-message drain. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern f32 Vec_xzDistance(void* a, void* b);

/* EN v1.0 0x8019C784  size: 1396b  fn_8019C784: per-rider wind lift physics -
 * track the rider while above the lift and in range, send the lift/drop
 * messages on state edges, and integrate the rise speed with ramp-up,
 * oscillation damping and player-mode handoff. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


/* EN v1.0 0x8019CD98  size: 1300b  windlift_update: fade the lift opacity
 * with its gamebit, spin up over the first second, then assign every nearby
 * group-0x16 object (and the player) to a rider slot and run the lift
 * physics on each. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern int randFn_80080100(int n);


/* EN v1.0 0x8019EC34  size: 1908b  babycloudrunner_update: full runner brain -
 * despawn on its gamebit, run the captured/timer flow, follow its rom curve
 * while fleeing, hand off to the nearest sandworm, and once freed steer home
 * to the roost point. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset




/* EN v1.0 0x8019D9F0  size: 2112b  fn_8019D9F0: main crystal beam update -
 * collect the three pylon positions from messages, re-request missing ones,
 * emit the beam particles toward the crystal (and down from each pylon),
 * ramp the convergence charge, hum volume and per-beam chime timers. */
#pragma scheduling off
#pragma peephole off
void fn_8019D9F0(int* obj);
#pragma peephole reset
#pragma scheduling reset

extern int fn_80296A14(int p);
extern void dll_2E_func04(void* sub);
extern void dll_2E_func0C(int a, void* p);
extern void buttonDisable(int a, int b);
extern void characterDoEyeAnims(int* obj, void* p);
extern int lbl_80322954[];
extern u8 lbl_803DBE20;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E4134;
extern f32 lbl_803E4138;
extern f32 lbl_803E413C;
extern f32 lbl_803E4140;
extern f32 lbl_803E4144;
extern f32 lbl_803E4148;
extern f32 lbl_803E414C;
extern f32 lbl_803E4150;
extern f32 lbl_803E4154;
extern f32 lbl_803E4158;
extern f32 lbl_803E415C;
extern f32 lbl_803E412C;

/* EN v1.0 0x8019B4C8  size: 3800b  waterSpellStone1Fn_8019b4c8: cfguardian
 * brain - sixteen-state quest progression for the CloudRunner guardian, with
 * sandworm avoidance, path flights, landing physics, sequenced triggers and
 * idle chatter. */
#pragma scheduling off
#pragma peephole off
int waterSpellStone1Fn_8019b4c8(int* obj)
{
    extern int hitDetectFn_800658a4(int* obj, f32 x, f32 y, f32 z, f32* out, int p); /* #57 */
    extern void fn_8019AE3C(int* obj, void* evbuf, void* p); /* #57 */
    extern int fn_8019AF64(int* obj, void* path, f32 f, int phase, void* spd); /* #57 */
    u8* def;
    char* player;
    CfGuardianState * sub;
    u8 evbuf[0x1c];
    f32 v[3];
    f32 k;
    f32 nearDist = lbl_803E412C;
    f32 ground = lbl_803E4130;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    evbuf[0x1b] = 0;
    sub = ((GameObject*)obj)->extra;
    sub->flagsA9B &= ~0x2;
    sub->moveSpeed = lbl_803E4134;
    player = (char*)Obj_GetPlayerObject();
    ObjTrigger_UpdateIdBlockFlag((int)obj);
    if (*(s8*)(def + 0x19) == 1 && GameBit_Get(0x57) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        return 0;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
    switch (sub->questState)
    {
    case 0:
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x94f) != 0)
        {
            sub->questState = 1;
        }
        break;
    case 1:
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x4e) != 0)
        {
            sub->questState = 3;
            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
            ((GameObject*)obj)->unkF4 = 0;
            GameBit_Set(0x48, 1);
            sub->flagsA9B |= 1;
        }
        break;
    case 2:
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        sub->flagsA9B |= 2;
        if (fn_8019AF64(obj, (u8*)sub + 0x6bc, lbl_803E4138, 0, (u8*)sub + 0x7fc) != 0)
        {
            sub->flagsA9B &= ~1;
            sub->questState = 4;
        }
        break;
    case 3:
        (*gObjectTriggerInterface)->runSequence(2, obj, -1);
        GameBit_Set(0x60, 1);
        sub->questState = 2;
        break;
    case 4:
        if (GameBit_Get(0x57) != 0)
        {
            if (*(s8*)(def + 0x19) != 1)
            {
                sub->questState = 0xf;
                sub->chatterAlt = 0;
            }
            else
            {
                sub->questState = 0xe;
                sub->chatterAlt = 0;
            }
        }
        else if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
            sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
        }
        break;
    case 6:
        if (sub->landingPhase == 0)
        {
            if (sub->chatterState == 2)
            {
                sub->chatterState = 1;
            }
        }
        else
        {
            if (sub->landingPhase >= 2)
            {
                ((GameObject*)obj)->anim.velocityX = lbl_803E4110;
                ((GameObject*)obj)->anim.velocityZ = lbl_803E4110;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)
                    ->anim.localPosY;
                hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                     ((GameObject*)obj)->anim.localPosZ, &ground, 0);
                *(s16*)obj = (s16)((0xc0 << (*(s16*)obj + 8)) >> 1);
                (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~0x400;
                if (ground <= lbl_803E4130)
                {
                    sub->landingPhase = 2;
                    ((GameObject*)obj)->anim.localPosY -= ground;
                    sub->chatterState = 1;
                    ((GameObject*)obj)->unkF4 = 0;
                    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E4110, 0);
                    {
                        char* pt = (char*)findRomCurvePointNearObject(obj, 0, 0, 2);
                        f32 d;
                        sub->homeX = *(f32*)(pt + 8);
                        sub->homeY = *(f32*)(pt + 0xc);
                        sub->homeZ = *(f32*)(pt + 0x10);
                        sub->homeYaw = (s16)(*(s8*)(pt + 0x2c) << 8);
                        d = sub->homeY - ((GameObject*)obj)->anim.localPosY;
                        d = (d >= lbl_803E4110) ? d : -d;
                        if (d < lbl_803E413C)
                        {
                            ObjGroup_AddObject(obj, 0x16);
                            sub->questState = 7;
                            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
                        }
                    }
                }
                else
                {
                    ((GameObject*)obj)->anim.velocityY -= lbl_803E4140;
                }
            }
            else
            {
                f32 w = lbl_803E4144 * ((GameObject*)obj)->anim.velocityY;
                w = (w >= lbl_803E4110) ? w : -w;
                *(s16*)obj = (f32) * (s16*)obj + w;
                sub->moveSpeed = lbl_803E4148;
                if (GameBit_Get(0x8e9) != 0)
                {
                    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E4110, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
                    ((GameObject*)obj)->anim.velocityY = lbl_803E4110;
                    ObjGroup_RemoveObject(obj, 0x16);
                    ((GameObject*)obj)->anim.velocityX = lbl_803E4110;
                    ((GameObject*)obj)->anim.velocityY = lbl_803E414C;
                    ((GameObject*)obj)->anim.velocityZ = lbl_803E4110;
                    sub->landingPhase = 2;
                    sub->flagsA9B &= ~1;
                }
            }
            if (sub->landingPhase < 2)
            {
                ((GameObject*)obj)->anim.localPosX = timeDelta * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)
                    ->anim.localPosX;
                ((GameObject*)obj)->anim.localPosZ = timeDelta * ((GameObject*)obj)->anim.velocityZ + ((GameObject*)obj)
                    ->anim.localPosZ;
                if (sub->bounceLatch != 0)
                {
                    ((GameObject*)obj)->anim.velocityX = lbl_803E4150 * -((GameObject*)obj)->anim.velocityX;
                    ((GameObject*)obj)->anim.velocityZ = lbl_803E4150 * -((GameObject*)obj)->anim.velocityZ;
                }
                v[0] = ((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX;
                v[1] = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->anim.previousLocalPosY;
                v[2] = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ;
                k = lbl_803E4154 * oneOverTimeDelta;
                v[0] = v[0] * k;
                v[1] = v[1] * k;
                v[2] = v[2] * k;
                ((GameObject*)obj)->anim.velocityX = v[0] + ((GameObject*)obj)->anim.velocityX;
                ((GameObject*)obj)->anim.velocityY = v[1] + ((GameObject*)obj)->anim.velocityY;
                ((GameObject*)obj)->anim.velocityZ = v[2] + ((GameObject*)obj)->anim.velocityZ;
                ((GameObject*)obj)->anim.velocityX = lbl_803E4138 * ((GameObject*)obj)->anim.velocityX;
                ((GameObject*)obj)->anim.velocityY = lbl_803E4138 * ((GameObject*)obj)->anim.velocityY;
                ((GameObject*)obj)->anim.velocityZ = lbl_803E4138 * ((GameObject*)obj)->anim.velocityZ;
            }
        }
        break;
    case 7:
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        sub->flagsA9B |= 2;
        if (fn_8019AF64(obj, (u8*)sub + 0x6bc, lbl_803E4138, 1, (u8*)sub + 0x7fc) != 0)
        {
            sub->questState = 8;
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
        }
        break;
    case 8:
        if ((void*)ObjGroup_FindNearestObject(3, obj, &nearDist) != NULL && nearDist < lbl_803E4158)
        {
            dll_2E_func04(sub);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
        if (nearDist > lbl_803E4158 && Vec_xzDistance(player + 0x18, (char*)obj + 0x18) < lbl_803E413C)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0)
            {
                dll_2E_func0C(0xf, (u8*)sub + 0xa68);
                sub->flagsA9B |= 5;
                lbl_80322954[sub->questState] = 0;
            }
            if (sub->chatterState == 2)
            {
                sub->chatterState = 1;
                sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
            }
        }
        else
        {
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0xe)
            {
                sub->chatterState = 2;
                sub->flagsA9B |= 5;
                dll_2E_func0A(0xe, (int*)((u8*)sub + 0xa68));
                lbl_80322954[sub->questState] = 0xe;
            }
        }
        if ((sub->flagsA9B & 4) != 0
            && fn_8019B1D8(obj, (int*)((u8*)sub + 0xa68), lbl_803E4128, (int)((u8*)sub + 0x7fc)) != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
            sub->flagsA9B &= ~0x5;
        }
        if (GameBit_Get(0x43) != 0)
        {
            sub->questState = 9;
            sub->chatterAlt = 0;
        }
        break;
    case 9:
        if ((void*)ObjGroup_FindNearestObject(3, obj, &nearDist) != NULL && nearDist < lbl_803E4158)
        {
            dll_2E_func04(sub);
        }
        if (nearDist > lbl_803E4158 && Vec_xzDistance(player + 0x18, (char*)obj + 0x18) < lbl_803E413C)
        {
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0)
            {
                dll_2E_func0C(0xf, (u8*)sub + 0xa68);
                sub->flagsA9B |= 5;
                lbl_80322954[sub->questState] = 0;
            }
            if (sub->chatterState == 2)
            {
                sub->chatterState = 1;
                sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
            }
        }
        else
        {
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0xe)
            {
                sub->chatterState = 2;
                sub->flagsA9B |= 5;
                dll_2E_func0A(0xe, (int*)((u8*)sub + 0xa68));
                lbl_80322954[sub->questState] = 0xe;
            }
        }
        if ((sub->flagsA9B & 4) != 0
            && fn_8019B1D8(obj, (int*)((u8*)sub + 0xa68), lbl_803E4128, (int)((u8*)sub + 0x7fc)) != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
            sub->flagsA9B &= ~0x5;
        }
        if (GameBit_Get(0x4be) != 0)
        {
            sub->questState = 0xa;
            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
            ((GameObject*)obj)->unkF4 = 0;
        }
        break;
    case 10:
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        sub->flagsA9B |= 2;
        if (fn_8019AF64(obj, (u8*)sub + 0x6bc, lbl_803E415C, 2, (u8*)sub + 0x7fc) != 0)
        {
            sub->questState = 0xb;
        }
        break;
    case 11:
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        ((GameObject*)obj)->anim.alpha = 0;
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        Obj_RemoveFromUpdateList(obj);
        ((GameObject*)obj)->anim.flags |= 0x4000;
        sub->questState = 0xf;
        break;
    case 12:
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x4b7) != 0)
        {
            (*gCameraInterface)->setTarget((int)obj);
            (*gObjectTriggerInterface)->runSequence(0xb, obj, -1);
            GameBit_Set(0x4b7, 0);
        }
        if (GameBit_Get(0x49a) != 0)
        {
            sub->questState = 0xd;
        }
        break;
    case 13:
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x4b7) != 0)
        {
            (*gCameraInterface)->setTarget((int)obj);
            (*gObjectTriggerInterface)->runSequence(0xa, obj, -1);
            GameBit_Set(0x4b7, 0);
        }
        if (GameBit_Get(0x4aa) != 0)
        {
            sub->questState = 0xe;
        }
        break;
    case 14:
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        break;
    case 15:
        ((GameObject*)obj)->anim.flags |= 0x4000;
        Obj_RemoveFromUpdateList(obj);
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        break;
    }
    dll_2E_func03(obj, sub);
    if (ObjTrigger_IsSet(obj) != 0)
    {
        buttonDisable(0, 0x100);
        if ((*gGameUIInterface)->isEventReady(0x2e8) != 0)
        {
            GameBit_Set(0x4ab, 1);
        }
        else if (sub->chatterState == 1)
        {
            int* tbl = (int*)seqStreamLookupFn_8007fff8(lbl_8032284C, 0xf, sub->questState);
            int pick;
            if (fn_80296A14((int)player) > 3)
            {
                pick = tbl[0];
            }
            else
            {
                pick = tbl[1];
            }
            if (sub->chatterPick % 2 != 0 && tbl[2] != -1)
            {
                pick = tbl[2];
            }
            sub->chatterPick += 1;
            if (pick != -1)
            {
                sub->chatterState = 2;
                (*gObjectTriggerInterface)->runSequence(pick, obj, -1);
            }
        }
    }
    if (GameBit_Get(0x902) != 0)
    {
        int* tbl2 = (int*)seqStreamLookupFn_8007fff8(lbl_8032284C, 0xf, sub->questState);
        if (tbl2[0] != -1)
        {
            sub->chatterState = 2;
            (*gObjectTriggerInterface)->runSequence(tbl2[0], obj, -1);
            GameBit_Set(0x902, 0);
        }
    }
    {
        int mv = lbl_80322954[sub->questState];
        if (mv != -1 && (sub->flagsA9B & 1) == 0 && ((GameObject*)obj)->anim.currentMove != mv)
        {
            ObjAnim_SetCurrentMove((int)obj, mv, lbl_803E4110, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x50);
        }
    }
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, sub->moveSpeed, (f32)framesThisStep,
                                                                    evbuf) != 0
        && (sub->flagsA9B & 1) != 0
        && ((GameObject*)obj)->anim.currentMove != 0x1a
        && ((GameObject*)obj)->anim.currentMove != 9)
    {
        sub->flagsA9B &= ~1;
    }
    fn_8019AE3C(obj, evbuf, &lbl_803DBE20);
    if (randFn_80080100(0x3c) != 0)
    {
        objAudioFn_800393f8((int)obj, (u8*)sub + 0x624, 0xdf, 0x1000, -1, 0);
    }
    objAnimFn_80038f38((int)obj, (u8*)sub + 0x624);
    characterDoEyeAnims(obj, (u8*)sub + 0x654);
    if (sub->questState != GameBit_Get(0x4b))
    {
        GameBit_Set(0x4b);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
