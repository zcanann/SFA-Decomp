/*
 * dim2lift - DIM2 boss (Icicle) lift-combat and baddie-animation
 * callbacks.  Contains the AI hit-decision functions (FUN_801ba*) that
 * choose the boss move based on player distance/angle/phase, the lift-
 * impact / tonsil-slam / breath-burst / blue-white-capture move
 * callbacks (FUN_801bb*), and the higher-level
 * DIMbossHitDetect_* / DIMbossAnim_* entry points called from the
 * object-descriptor vtable.
 */
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/dll/DIM/DIM2lift.h"
#include "main/dll/baddie_state.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_8000691c();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_80006b94();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern void Obj_FreeObject(int obj);
extern undefined4 FUN_800305f8();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 DIM2icicle_updateHitResponse();

extern undefined4 DAT_803265a0;
extern undefined4 DAT_803265e0;
extern undefined4 DAT_803266e0;
extern undefined4 DAT_80326708;
extern undefined4 DAT_80326714;
extern undefined4 DAT_80326724;
extern undefined4 DAT_80326734;
extern undefined4 DAT_803adc4d;
extern undefined4 DAT_803dcb98;
extern undefined4 DAT_803dcba0;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de800;
extern undefined4 DAT_803de804;
extern f64 DOUBLE_803e5848;
extern f64 DOUBLE_803e5878;
extern f32 lbl_803E5840;
extern f32 lbl_803E5844;
extern f32 lbl_803E5850;
extern f32 lbl_803E5854;
extern f32 lbl_803E5858;
extern f32 lbl_803E585C;
extern f32 lbl_803E5860;
extern f32 lbl_803E5864;
extern f32 lbl_803E5868;
extern f32 lbl_803E586C;
extern f32 lbl_803E5870;
extern f32 lbl_803E5880;
extern f32 lbl_803E5884;
extern f32 lbl_803E5888;
extern f32 lbl_803E588C;
extern f32 lbl_803E5890;
extern f32 lbl_803E5894;
extern f32 lbl_803E5898;
extern f32 lbl_803E589C;
extern f32 lbl_803E58A0;
extern f32 lbl_803E58A4;
extern f32 lbl_803E58A8;
extern f32 lbl_803E58AC;
extern f32 lbl_803E58B0;
extern f32 lbl_803E58B4;
extern f32 lbl_803E58B8;
extern f32 lbl_803E58BC;

extern f32 lbl_803E4BD8;
extern f32 lbl_803E4C24;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);
extern void** gPlayerInterface;
extern f32 lbl_803E4C00;
extern int lbl_80325AA0[6];
extern int* gBaddieControlInterface;
extern int lbl_80325960[16];
extern f32 lbl_803259A0[16];
extern f32 lbl_803E4C04;
extern u32 gDIMbossSequenceFlags;
extern int lbl_803DBF30;
extern f32 lbl_803E4BC4;
extern f32 lbl_803E4BC8;
extern f32 lbl_803E4BCC;
extern f32 lbl_803E4BD0;
extern f32 lbl_803E4BE8;
extern f32 lbl_803E4BEC;
extern f32 lbl_803E4BC0;
extern f32 lbl_803E4BD4;
extern f32 lbl_803E4C08;
extern f32 lbl_803E4C0C;
extern f32 lbl_803E4C10;
extern f32 lbl_803E4C14;
extern f32 lbl_803E4C18;
extern f32 lbl_803E4C1C;
extern f32 lbl_803E4C20;
extern f32 lbl_803E4BBC;
extern s16 lbl_80325AC8[30];
extern s16 lbl_803DBF38[4];
extern u8 gDIMbossAnimController[];

void FUN_801ba224(short* obj, int def)
{
    int target;

    obj[2] = (ushort) * (byte*)(def + 0x18) << 8;
    obj[1] = (ushort) * (byte*)(def + 0x19) << 8;
    *obj = (ushort) * (byte*)(def + 0x1a) << 8;
    if (*(byte*)(def + 0x1b) != 0)
    {
        *(float*)(obj + 4) =
            *(float*)(*(int*)(obj + 0x28) + 4) *
            ((float)((double)CONCAT44(0x43300000, (uint) * (byte*)(def + 0x1b)) - DOUBLE_803e5848) /
                lbl_803E5840);
    }
    *(float*)(*(int*)(obj + 0x5c) + 0x10) = lbl_803E5844;
    target = *(int*)(obj + 0x32);
    if (target != 0)
    {
        *(uint*)(target + 0x30) = *(uint*)(target + 0x30) | 0x810;
    }
    obj[0x58] = obj[0x58] | 0x2000;
    return;
}

undefined4
FUN_801ba2e0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             undefined4 param_9, int param_10)
{
    char animPhase;
    uint moveIdx;
    ushort distance;
    u8 auStack_16[2];
    short hitInfo[4];

    if ((*(char*)(param_10 + 0x346) != '\0') || (*(char*)(param_10 + 0x27b) != '\0'))
    {
        (**(code**)(*DAT_803dd738 + 0x14))
            (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, hitInfo, auStack_16, &distance);
        *(u8*)(param_10 + 0x346) = 0;
        if (distance < 0x5a)
        {
            if ((distance < 0x1f) ||
                (((1 < (ushort)(hitInfo[0] - 3U) && (hitInfo[0] != 0xb)) && (hitInfo[0] != 0xc))))
            {
                param_1 = (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 9);
            }
            else
            {
                param_1 = (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 2);
            }
        }
        else if ((hitInfo[0] == 0) || (hitInfo[0] == 0xf))
        {
            *(u8*)(param_10 + 0x346) = 0;
            if ((distance < 0x1aa) ||
                (moveIdx = (**(code**)(*DAT_803dd738 + 0x18))((double)lbl_803E5850, param_9, param_10),
                    (moveIdx & 1) == 0))
            {
                if (distance < 0xfa)
                {
                    param_1 = (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 3);
                }
                else
                {
                    if (6 < DAT_803de804)
                    {
                        DAT_803de804 = 0;
                    }
                    animPhase = *(char*)(param_10 + 0x354);
                    if (animPhase == '\x02')
                    {
                        moveIdx = (uint)DAT_803de804;
                        DAT_803de804 = DAT_803de804 + 1;
                        param_1 = (**(code**)(*DAT_803dd70c + 0x14))
                            (param_9, param_10, (int)*(short*)(&DAT_80326724 + moveIdx * 2));
                    }
                    else
                    {
                        if (animPhase < '\x02')
                        {
                            if ('\0' < animPhase)
                            {
                                moveIdx = (uint)DAT_803de804;
                                DAT_803de804 = DAT_803de804 + 1;
                                param_1 = (**(code**)(*DAT_803dd70c + 0x14))
                                    (param_9, param_10, (int)*(short*)(&DAT_80326734 + moveIdx * 2));
                                goto LAB_801ba764;
                            }
                        }
                        else if (animPhase < '\x04')
                        {
                            moveIdx = (uint)DAT_803de804;
                            DAT_803de804 = DAT_803de804 + 1;
                            param_1 = (**(code**)(*DAT_803dd70c + 0x14))
                                (param_9, param_10, (int)*(short*)(&DAT_80326714 + moveIdx * 2));
                            goto LAB_801ba764;
                        }
                        param_1 = (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 3);
                    }
                }
            }
            else
            {
                moveIdx = randomGetRange(0, 5);
                param_1 = (**(code**)(*DAT_803dd70c + 0x14))
                    (param_9, param_10, (int)*(short*)(&DAT_80326708 + moveIdx * 2));
            }
        }
        else
        {
            param_1 = (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 2);
        }
    }
LAB_801ba764:
    if ((*(short*)(param_10 + 0x274) == 3) || (*(short*)(param_10 + 0x274) == 7))
    {
        DAT_803adc4d = DAT_803adc4d | 1;
    }
    else
    {
        DAT_803adc4d = DAT_803adc4d & 0xfe;
    }
    DIM2icicle_updateHitResponse(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    return 0;
}

undefined4
FUN_801ba6d8(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             int param_10)
{
    short controlMode;
    uint moveIdx;
    int state;
    ushort distance;
    u8 auStack_16[2];
    short hitInfo[4];

    state = *(int*)&((GameObject*)param_9)->extra;
    if ((*(char*)(param_10 + 0x346) != '\0') || (*(char*)(param_10 + 0x27b) != '\0'))
    {
        (**(code**)(*DAT_803dd738 + 0x14))
            (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, hitInfo, auStack_16, &distance);
        *(u8*)(param_10 + 0x346) = 0;
        if (distance < 0x5a)
        {
            if ((distance < 0x1f) ||
                (((1 < (ushort)(hitInfo[0] - 3U) && (hitInfo[0] != 0xb)) && (hitInfo[0] != 0xc))))
            {
                param_1 = (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 9);
            }
            else
            {
                param_1 = (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 2);
            }
        }
        else if ((hitInfo[0] == 0) || (hitInfo[0] == 0xf))
        {
            *(u8*)(param_10 + 0x346) = 0;
            if ((distance < 0xf1) ||
                (moveIdx = (**(code**)(*DAT_803dd738 + 0x18))((double)lbl_803E5854, param_9, param_10),
                    (moveIdx & 1) == 0))
            {
                if ((*(ushort*)(state + 0x400) & 4) == 0)
                {
                    param_1 = (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 3);
                }
                else
                {
                    moveIdx = randomGetRange(0, 1);
                    param_1 = (**(code**)(*DAT_803dd70c + 0x14))
                        (param_9, param_10, (int)*(short*)(&DAT_803dcba0 + moveIdx * 2));
                }
            }
            else
            {
                moveIdx = randomGetRange(0, 5);
                param_1 = (**(code**)(*DAT_803dd70c + 0x14))
                    (param_9, param_10, (int)*(short*)(&DAT_80326708 + moveIdx * 2));
            }
        }
        else
        {
            param_1 = (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 2);
        }
    }
    controlMode = *(short*)(param_10 + 0x274);
    if (((controlMode == 1) || (controlMode == 4)) || (controlMode == 5))
    {
        DAT_803adc4d = DAT_803adc4d & 0xfe;
    }
    else
    {
        DAT_803adc4d = DAT_803adc4d | 1;
    }
    DIM2icicle_updateHitResponse(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    return 0;
}

undefined4
FUN_801ba9ec(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int player;
    int state;

    FUN_80017a98();
    state = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27b) != '\0')
    {
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(u8*)(param_10 + 0x25f) = 0;
        *(u8*)(param_10 + 0x349) = 0;
        ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode &
            0x7f;
        player = FUN_80017a98();
        ObjMsg_SendToObject(player, 0xe0000, param_9, 0);
        GameBit_Set((int)*(short*)(state + 0x3f4), 0);
        GameBit_Set((int)*(short*)(state + 0x3f2), 1);
        if (*(int*)&((GameObject*)param_9)->anim.placementData == 0)
        {
            Obj_FreeObject((int)param_9);
        }
    }
    return 0;
}

undefined4
FUN_801babd4(int param_1, int param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5,
             undefined4 param_6, undefined4 param_7, undefined4 param_8)
{
    float animSpeed;
    double shakeZ;
    double scale;
    double shakeY;
    undefined8 in_f4;
    undefined8 in_f5;
    undefined8 in_f6;
    undefined8 in_f7;
    undefined8 in_f8;

    if (lbl_803E5858 < ((GameObject*)param_1)->anim.currentMoveProgress)
    {
        DAT_803de800 = DAT_803de800 & 0xffffffdf;
    }
    if (*(char*)(param_2 + 0x27a) != '\0')
    {
        DAT_803de800 = DAT_803de800 | 0x8020;
        FUN_800069bc();
        shakeY = (double)lbl_803E5864;
        FUN_8000691c((double)lbl_803E585C, (double)lbl_803E5860, shakeY);
        FUN_80006b94((double)lbl_803E5868);
        *(undefined2*)(param_1 + 0xa2) = 0xffff;
        scale = (double)lbl_803E586C;
        *(float*)(param_2 + 0x2a0) =
            (float)(scale * (double)(float)((double)CONCAT44(0x43300000,
                                                             (int)*(char*)(param_2 + 0x354) + 1U ^
                                                             0x80000000) - DOUBLE_803e5878));
        animSpeed = lbl_803E5870;
        shakeZ = (double)lbl_803E5870;
        *(float*)(param_2 + 0x280) = lbl_803E5870;
        *(float*)(param_2 + 0x284) = animSpeed;
        if (*(char*)(param_2 + 0x27a) != '\0')
        {
            FUN_800305f8(shakeZ, scale, shakeY, in_f4, in_f5, in_f6, in_f7, in_f8, param_1, 0x15, 0, param_4, param_5,
                         param_6, param_7, param_8);
            *(u8*)(param_2 + 0x346) = 0;
        }
    }
    (**(code**)(*DAT_803dd70c + 0x34))(param_1, param_2, 0, 0, &DAT_803dcb98);
    return 0;
}

undefined4
FUN_801bad7c(int param_1, int param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5,
             undefined4 param_6, undefined4 param_7, undefined4 param_8)
{
    float animSpeed;
    int state;
    double zeroProgress;
    double shakeY;
    double shakeZ;
    undefined8 in_f4;
    undefined8 in_f5;
    undefined8 in_f6;
    undefined8 in_f7;
    undefined8 in_f8;

    state = *(int*)&((GameObject*)param_1)->extra;
    if (*(char*)(param_2 + 0x27a) != '\0')
    {
        DAT_803de800 = DAT_803de800 | 0x2000;
        FUN_800069bc();
        shakeY = (double)lbl_803E5860;
        shakeZ = (double)lbl_803E5864;
        FUN_8000691c((double)lbl_803E585C, shakeY, shakeZ);
        FUN_80006b94((double)lbl_803E5868);
        *(undefined2*)(param_1 + 0xa2) = 0xffff;
        *(float*)(param_2 + 0x2a0) = lbl_803E5880;
        animSpeed = lbl_803E5870;
        zeroProgress = (double)lbl_803E5870;
        *(float*)(param_2 + 0x280) = lbl_803E5870;
        *(float*)(param_2 + 0x284) = animSpeed;
        if (*(char*)(param_2 + 0x27a) != '\0')
        {
            FUN_800305f8(zeroProgress, shakeY, shakeZ, in_f4, in_f5, in_f6, in_f7, in_f8, param_1, 0xe, 0, param_4, param_5,
                         param_6, param_7, param_8);
            *(u8*)(param_2 + 0x346) = 0;
        }
        if (*(short*)(state + 0x402) == 1)
        {
            *(float*)(*(int*)(state + 0x40c) + 0xa8) = lbl_803E5884;
        }
    }
    (**(code**)(*DAT_803dd70c + 0x34))(param_1, param_2, 0, 1, &DAT_803dcb98);
    return 0;
}

undefined4
FUN_801baefc(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float animSpeed;
    undefined4 hitFlag;

    *(float*)(param_10 + 0x2a0) = lbl_803E5888;
    animSpeed = lbl_803E5870;
    *(float*)(param_10 + 0x280) = lbl_803E5870;
    *(float*)(param_10 + 0x284) = animSpeed;
    hitFlag = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0xf, 0, hitFlag, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        DAT_803de800 = DAT_803de800 | 0x4004;
        FUN_80006824(param_9, SFXwmap_swoosh);
        FUN_800069bc();
        FUN_8000691c((double)lbl_803E5860, (double)lbl_803E588C, (double)lbl_803E5890);
        FUN_80006b94((double)lbl_803E5894);
        GameBit_Set(0x26b, 1);
    }
    return 0;
}

undefined4
FUN_801bb080(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float animSpeed;
    uint variant;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        *(undefined2*)(param_9 + 0xa2) = 0xffff;
        animSpeed = lbl_803E5870;
        *(float*)(param_10 + 0x280) = lbl_803E5870;
        *(float*)(param_10 + 0x284) = animSpeed;
        *(float*)(param_10 + 0x2a0) = lbl_803E5898;
        variant = randomGetRange(0, 1);
        if (variant == 0)
        {
            if (*(char*)(param_10 + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 0xc, 0, param_12, param_13, param_14, param_15, param_16);
                *(u8*)(param_10 + 0x346) = 0;
            }
        }
        else if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 0xd, 0, param_12, param_13, param_14, param_15, param_16);
            *(u8*)(param_10 + 0x346) = 0;
        }
    }
    (**(code**)(*DAT_803dd70c + 0x34))(param_9, param_10, 0, 0, &DAT_803266e0);
    (**(code**)(*DAT_803dd70c + 0x34))(param_9, param_10, 7, 1, &DAT_803266e0);
    return 0;
}

undefined4
FUN_801bb2a0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float animSpeed;
    undefined4 hitFlag;

    hitFlag = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 9, 1, -1);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        *(float*)(param_10 + 0x2a0) = lbl_803E589C;
        if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 0x13, 0, hitFlag, param_13, param_14, param_15, param_16);
            *(u8*)(param_10 + 0x346) = 0;
        }
        *(undefined2*)(param_9 + 0xa2) = 0xffff;
        animSpeed = lbl_803E5870;
        *(float*)(param_10 + 0x280) = lbl_803E5870;
        *(float*)(param_10 + 0x284) = animSpeed;
    }
    (**(code**)(*DAT_803dd70c + 0x34))(param_9, param_10, 0, 1, &DAT_803266e0);
    (**(code**)(*DAT_803dd70c + 0x30))(param_1, param_9, param_10, 0xf0);
    return 0;
}

#pragma scheduling off
#pragma peephole off
typedef struct DIM2icicleBlueWhiteEffectPlacement {
    ObjPlacement base;
    u8 pad18[0x1E - 0x18];
    s16 field1E;
    s16 field20;
    u8 pad22[0x24 - 0x22];
} DIM2icicleBlueWhiteEffectPlacement;

STATIC_ASSERT(sizeof(DIM2icicleBlueWhiteEffectPlacement) == 0x24);

void DIM2icicle_createStateLight(int obj, u8 isGreen)
{
    extern int objCreateLight(int, int);
    extern void modelLightStruct_setLightKind(int, int);
    extern void modelLightStruct_setPosition(int, f32, f32, f32);
    extern void modelLightStruct_setDiffuseColor(int, int, int, int, int);
    extern void modelLightStruct_setSpecularColor(int, int, int, int, int);
    extern void modelLightStruct_setupGlow(int, int, int, int, int, int, f32);
    extern void modelLightStruct_setDistanceAttenuation(int, f32, f32);
    extern void lightSetField4D(int, int);
    extern void modelLightStruct_setEnabled(int, int, f32);
    extern void modelLightStruct_setDiffuseTargetColor(int, int, int, int, int);
    extern void modelLightStruct_setSpecularTargetColor(int, int, int, int, int);
    extern void modelLightStruct_startColorFade(int, int, int);
    extern void modelLightStruct_setAffectsAabbLightSelection(int, int);
    extern void modelLightStruct_setGlowProjectionRadius(int, f32);
    extern f32 lbl_803E4BBC;
    extern f32 lbl_803E4BD8;
    extern f32 lbl_803E4C28;
    extern f32 lbl_803E4C2C;
    extern f32 lbl_803E4C30;
    int* lightSlot = (int*)*(int*)&((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;

    if (*(void**)lightSlot != NULL) return;

    lightSlot[0] = objCreateLight(0, 1);
    if (*(void**)lightSlot == NULL) return;

    modelLightStruct_setLightKind(lightSlot[0], 2);
    modelLightStruct_setPosition(lightSlot[0], ((f32*)lightSlot)[0x16], ((f32*)lightSlot)[0x17],
                                 ((f32*)lightSlot)[0x18]);

    if (isGreen != 0)
    {
        modelLightStruct_setDiffuseColor(lightSlot[0], 0, 255, 0, 255);
        modelLightStruct_setSpecularColor(lightSlot[0], 0, 255, 0, 255);
        modelLightStruct_setupGlow(lightSlot[0], 0, 0, 255, 0, 192, lbl_803E4C28);
    }
    else
    {
        modelLightStruct_setDiffuseColor(lightSlot[0], 255, 0, 0, 255);
        modelLightStruct_setSpecularColor(lightSlot[0], 255, 0, 0, 255);
        modelLightStruct_setupGlow(lightSlot[0], 0, 255, 0, 0, 192, lbl_803E4C2C);
    }

    modelLightStruct_setDistanceAttenuation(lightSlot[0], lbl_803E4C2C, lbl_803E4C30);
    lightSetField4D(lightSlot[0], 1);
    modelLightStruct_setEnabled(lightSlot[0], 1, lbl_803E4BD8);
    modelLightStruct_setDiffuseTargetColor(lightSlot[0], 64, 0, 0, 64);
    modelLightStruct_setSpecularTargetColor(lightSlot[0], 64, 0, 0, 64);
    modelLightStruct_startColorFade(lightSlot[0], 2, 40);
    modelLightStruct_setAffectsAabbLightSelection(lightSlot[0], 1);
    modelLightStruct_setGlowProjectionRadius(lightSlot[0], lbl_803E4BBC);
}

undefined4
#pragma scheduling on
#pragma peephole on
FUN_801bb450(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float animSpeed;
    undefined4 result;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        *(float*)(param_10 + 0x2a0) = lbl_803E58A0;
        if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 0x12, 0, param_12, param_13, param_14, param_15, param_16);
            *(u8*)(param_10 + 0x346) = 0;
        }
        *(undefined2*)(param_9 + 0xa2) = 0xffff;
        animSpeed = lbl_803E5870;
        *(float*)(param_10 + 0x280) = lbl_803E5870;
        *(float*)(param_10 + 0x284) = animSpeed;
    }
    if ((lbl_803E58A4 < ((GameObject*)param_9)->anim.currentMoveProgress) || (*(char*)(param_10 + 0x346) != '\0'))
    {
        result = 8;
    }
    else
    {
        if (lbl_803E58A8 < ((GameObject*)param_9)->anim.currentMoveProgress)
        {
            DAT_803de800 = DAT_803de800 | 0x10;
        }
        (**(code**)(*DAT_803dd70c + 0x34))(param_9, param_10, 0, 5, &DAT_803266e0);
        (**(code**)(*DAT_803dd70c + 0x30))(param_1, param_9, param_10, 0xf0);
        result = 0;
    }
    return result;
}

undefined4
FUN_801bb5e8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float animSpeed;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        *(float*)(param_10 + 0x2a0) = lbl_803E58AC;
        if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
            *(u8*)(param_10 + 0x346) = 0;
        }
        *(undefined2*)(param_9 + 0xa2) = 0xffff;
        animSpeed = lbl_803E5870;
        *(float*)(param_10 + 0x280) = lbl_803E5870;
        *(float*)(param_10 + 0x284) = animSpeed;
    }
    if (((GameObject*)param_9)->anim.currentMoveProgress <= lbl_803E58B0)
    {
        if (lbl_803E58B4 < ((GameObject*)param_9)->anim.currentMoveProgress)
        {
            DAT_803de800 = DAT_803de800 | 0x40;
        }
    }
    else
    {
        DAT_803de800 = DAT_803de800 & 0xffffffbf;
    }
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        DAT_803de800 = DAT_803de800 | 0x10000;
    }
    (**(code**)(*DAT_803dd70c + 0x34))(param_9, param_10, 0, 3, &DAT_803266e0);
    (**(code**)(*DAT_803dd70c + 0x30))(param_1, param_9, param_10, 0xf0);
    return 0;
}

undefined4
FUN_801bb798(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float animSpeed;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        *(float*)(param_10 + 0x2a0) = lbl_803E5898;
        if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
            *(u8*)(param_10 + 0x346) = 0;
        }
        *(undefined2*)(param_9 + 0xa2) = 0xffff;
        animSpeed = lbl_803E5870;
        *(float*)(param_10 + 0x280) = lbl_803E5870;
        *(float*)(param_10 + 0x284) = animSpeed;
    }
    if (((GameObject*)param_9)->anim.currentMoveProgress <= lbl_803E58B0)
    {
        if (lbl_803E58B8 < ((GameObject*)param_9)->anim.currentMoveProgress)
        {
            DAT_803de800 = DAT_803de800 | 0x40;
        }
    }
    else
    {
        DAT_803de800 = DAT_803de800 & 0xffffffbf;
    }
    if ((*(uint*)(param_10 + 0x314) & 0x200) != 0)
    {
        DAT_803de800 = DAT_803de800 | 0x10000;
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & 0xfffffdff;
    }
    (**(code**)(*DAT_803dd70c + 0x34))(param_9, param_10, 0, 3, &DAT_803266e0);
    (**(code**)(*DAT_803dd70c + 0x30))(param_1, param_9, param_10, 0xf0);
    return 0;
}

undefined4
FUN_801bb954(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float animSpeed;
    uint variant;
    undefined4 hitFlag;

    hitFlag = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 9, 1, -1);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        *(undefined2*)(param_9 + 0xa2) = 0xffff;
        animSpeed = lbl_803E5870;
        *(float*)(param_10 + 0x280) = lbl_803E5870;
        *(float*)(param_10 + 0x284) = animSpeed;
        variant = randomGetRange(0, 1);
        if (variant == 0)
        {
            if (*(char*)(param_10 + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 0x10, 0, hitFlag, param_13, param_14, param_15, param_16);
                *(u8*)(param_10 + 0x346) = 0;
            }
            *(float*)(param_10 + 0x2a0) = lbl_803E589C;
        }
        else
        {
            if (*(char*)(param_10 + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 0xb, 0, hitFlag, param_13, param_14, param_15, param_16);
                *(u8*)(param_10 + 0x346) = 0;
            }
            *(float*)(param_10 + 0x2a0) = lbl_803E5898;
        }
    }
    if ((*(uint*)(param_10 + 0x314) & 0x200) != 0)
    {
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & 0xfffffdff;
        DAT_803de800 = DAT_803de800 | 5;
    }
    variant = randomGetRange(0, 1);
    (**(code**)(*DAT_803dd70c + 0x34))(param_9, param_10, 0, variant, &DAT_803266e0);
    (**(code**)(*DAT_803dd70c + 0x30))(param_1, param_9, param_10, 0xf0);
    return 0;
}

undefined4
FUN_801bbbc8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10)
{
    ushort* hitInfoPtr;
    undefined* scratchB;
    undefined* scratchA;
    int ctrlIface;
    undefined4 in_r10;
    u8 auStack_28[2];
    u8 auStack_26[2];
    ushort hitInfo[6];

    *(float*)(param_10 + 0x280) = lbl_803E5870;
    if (((*(char*)(param_10 + 0x346) != '\0') || (*(char*)(param_10 + 0x27a) != '\0')) ||
        (((GameObject*)param_9)->anim.currentMove == 1))
    {
        hitInfoPtr = hitInfo;
        scratchB = auStack_26;
        scratchA = auStack_28;
        ctrlIface = *DAT_803dd738;
        (**(code**)(ctrlIface + 0x14))(param_9, *(undefined4*)(param_10 + 0x2d0), 0x10);
        FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, *(undefined4*)(&DAT_803265a0 + (uint)hitInfo[0] * 4), 0, hitInfoPtr, scratchB,
                     scratchA, ctrlIface, in_r10);
        *(undefined4*)(param_10 + 0x2a0) = *(undefined4*)(&DAT_803265e0 + (uint)hitInfo[0] * 4);
        *(u8*)(param_10 + 0x346) = 0;
    }
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 8);
    return 0;
}

undefined4
FUN_801bbd68(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9, int param_10
             , undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 2, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E58BC;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 1);
    (**(code**)(*DAT_803dd70c + 0x30))(param_1, param_9, param_10, 4);
    return 0;
}

undefined4
FUN_801bbea0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    bool isStarting;
    float animSpeed;

    isStarting = *(char*)(param_10 + 0x27a) != '\0';
    if (isStarting)
    {
        if (isStarting)
        {
            FUN_800305f8((double)lbl_803E5870, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 1, 0, param_12, param_13, param_14, param_15, param_16);
            *(u8*)(param_10 + 0x346) = 0;
        }
        animSpeed = lbl_803E5870;
        *(float*)(param_10 + 0x280) = lbl_803E5870;
        *(float*)(param_10 + 0x284) = animSpeed;
        *(undefined2*)(param_9 + 0xa2) = 0xffff;
    }
    return 0;
}

int DIMbossAnim_hasMoveDone(int unused, int* p) { return *(s8*)&((BaddieState*)p)->moveDone != 0; }

#pragma scheduling off
#pragma peephole off
int DIMbossHitDetect_applyForwardMove(int* obj, u8* state, f32 weight)
{
    if ((s8)state[634] != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E4BD8, 0);
        state[838] = 0;
    }
    ((BaddieState*)state)->moveSpeed = lbl_803E4C24;
    ((void(*)(int*, u8*, f32, int))((void**)*gPlayerInterface)[8])(obj, state, weight, 1);
    ((void(*)(int*, u8*, f32, int))((void**)*gPlayerInterface)[12])(obj, state, weight, 4);
    return 0;
}

void DIM2icicle_spawnBlueWhiteEffect(DIMbossEffectMarker* source, f32* velocity)
{
    GameObject* spawnedObj;
    DIM2icicleBlueWhiteEffectPlacement* setup;
    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(36, 656);
        setup->base.posX = source->x;
        setup->base.posY = source->y;
        setup->base.posZ = source->z;
        setup->base.unk04[0] = 1;
        setup->base.unk04[1] = 1;
        setup->base.unk04[2] = 255;
        setup->base.unk04[3] = 255;
        setup->field1E = -1;
        setup->field20 = -1;
        spawnedObj = (GameObject*)Obj_SetupObject(setup, 5, -1, -1, (void*)0);
        if (spawnedObj != NULL)
        {
            spawnedObj->anim.velocityX = velocity[0];
            spawnedObj->anim.velocityY = velocity[1];
            spawnedObj->anim.velocityZ = velocity[2];
        }
    }
}

int DIMbossHitDetect_resetIdleMove(int* obj, u8* state)
{
    if ((s8)state[634] != 0)
    {
        f32 fz;
        if ((s8)state[634] != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E4BD8, 0);
            state[838] = 0;
        }
        fz = lbl_803E4BD8;
        ((BaddieState*)state)->animSpeedA = fz;
        ((BaddieState*)state)->animSpeedB = fz;
        ((GameObject*)obj)->anim.activeMove = -1;
    }
    return 0;
}

#pragma scheduling on
#pragma peephole on
int DIMbossAnim_selectTargetControlMode(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    switch (((GroundBaddieState*)state)->targetState)
    {
    case 1: return 5;
    case 2: return 6;
    case 4: return 4;
    case 0: return 2;
    case 3: return 2;
    default: return 2;
    }
}

#pragma scheduling off
#pragma peephole off
int DIMbossAnim_finishDefeat(int obj, int p2)
{
    extern void*Obj_GetPlayerObject(void);
    int sub;

    Obj_GetPlayerObject();
    sub = *(int*)&((GameObject*)obj)->extra;

    if ((s32)(s8)((BaddieState*)p2)->moveJustStartedB != 0)
    {
        *(int*)&((BaddieState*)p2)->targetObj = 0;
        ((BaddieState*)p2)->physicsActive = 0;
        ((BaddieState*)p2)->hasTarget = 0;
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x80);
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0xE0000, obj, 0);
        GameBit_Set(((GroundBaddieState*)sub)->gameBitB, 0);
        GameBit_Set(((GroundBaddieState*)sub)->gameBitA, 1);
        if (((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject(obj);
            return 0;
        }
    }
    return 0;
}

int DIMbossHitDetect_liftImpact(int obj, int p2)
{
    f32 zeroProgress;
    extern void Camera_EnableViewYOffset(void);
    extern void CameraShake_Start(f32, f32, f32);
    extern void doRumble(f32);
    extern u32 gDIMbossSequenceFlags;
    extern f32 lbl_803E4BC8;
    extern f32 lbl_803E4BD8;
    extern f32 lbl_803E4BF0;
    extern f32 lbl_803E4BF4;
    extern f32 lbl_803E4BF8;
    extern f32 lbl_803E4BFC;

    ((BaddieState*)p2)->moveSpeed = lbl_803E4BF0;
    zeroProgress = lbl_803E4BD8;
    ((BaddieState*)p2)->animSpeedA = zeroProgress;
    ((BaddieState*)p2)->animSpeedB = zeroProgress;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);

    if ((s32)(s8)((BaddieState*)p2)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 15, lbl_803E4BD8, 0);
        ((BaddieState*)p2)->moveDone = 0;
    }

    if ((*(int*)&((BaddieState*)p2)->eventFlags & 0x1) != 0)
    {
        gDIMbossSequenceFlags |= 0x4004;
        Sfx_PlayFromObject(obj, SFXwmap_swoosh);
        Camera_EnableViewYOffset();
        CameraShake_Start(lbl_803E4BC8, lbl_803E4BF4, lbl_803E4BF8);
        doRumble(lbl_803E4BFC);
        GameBit_Set(619, 1);
    }
    return 0;
}

int DIMbossAnim_returnToIdleWhenDone(int obj, int runtime)
{
    if (*(s8*)&((BaddieState*)runtime)->moveDone != 0)
    {
        (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 0);
    }
    return 0;
}

int DIMbossHitDetect_chooseIdleTaunt(int obj, int runtime)
{
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        f32 v;
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C00;
        if ((int)randomGetRange(0, 1) != 0)
        {
            if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 0xd, lbl_803E4BD8, 0);
                ((BaddieState*)runtime)->moveDone = 0;
            }
        }
        else
        {
            if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 0xc, lbl_803E4BD8, 0);
                ((BaddieState*)runtime)->moveDone = 0;
            }
        }
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 0, lbl_80325AA0);
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 7, 1, lbl_80325AA0);
    return 0;
}

int DIMbossHitDetect_trackTargetMove(int obj, int runtime, f32 hitAmount)
{
    u16 local_c;
    s16 local_a;
    s16 local_8;
    ((BaddieState*)runtime)->animSpeedA = lbl_803E4BD8;
    if (*(s8*)&((BaddieState*)runtime)->moveDone != 0 || *(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0 || ((
        GameObject*)obj)->anim.currentMove == 1)
    {
        (*(int (**)(int, int, int, u16*, s16*, s16*))(*(int*)gBaddieControlInterface + 0x14))(
            obj, *(int*)&((BaddieState*)runtime)->targetObj, 0x10, &local_c, &local_a, &local_8);
        ObjAnim_SetCurrentMove(obj, lbl_80325960[local_c], lbl_803E4BD8, 0);
        ((BaddieState*)runtime)->moveSpeed = lbl_803259A0[local_c];
        ((BaddieState*)runtime)->moveDone = 0;
    }
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, runtime, hitAmount, 8);
    return 0;
}

int DIMbossHitDetect_lungeAttack(int obj, int runtime, f32 hitAmount)
{
    ObjHits_SetHitVolumeSlot(obj, 9, 1, -1);
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        f32 v;
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C04;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E4BD8, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 1, lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, hitAmount, 0xf0);
    return 0;
}

int DIMbossHitDetect_liftSlam(int obj, int runtime)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        f32 v;
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_2000;
        Camera_EnableViewYOffset();
        CameraShake_Start(lbl_803E4BC4, lbl_803E4BC8, lbl_803E4BCC);
        doRumble(lbl_803E4BD0);
        ((GameObject*)obj)->anim.activeMove = -1;
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4BE8;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xe, v, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        if (((GroundBaddieState*)state)->targetState == 1)
        {
            *(f32*)(*(int*)&((GroundBaddieState*)state)->control + 0xa8) = lbl_803E4BEC;
        }
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 1, &lbl_803DBF30);
    return 0;
}

int DIMbossHitDetect_tonsilSlam(int obj, int runtime)
{
    f32 v;
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E4BC0)
    {
        gDIMbossSequenceFlags &= ~DIMBOSS_SEQUENCE_FLAG_0020;
    }
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        gDIMbossSequenceFlags |= (u64)DIMBOSS_SEQUENCE_FLAGS_TONSIL_IMPACT;
        Camera_EnableViewYOffset();
        CameraShake_Start(lbl_803E4BC4, lbl_803E4BC8, lbl_803E4BCC);
        doRumble(lbl_803E4BD0);
        ((GameObject*)obj)->anim.activeMove = -1;
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4BD4 * (f32)(*(s8*)&((BaddieState*)runtime)->hitPoints + 1);
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x15, v, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 0, &lbl_803DBF30);
    return 0;
}

int DIMbossHitDetect_breathBurst(int obj, int runtime, f32 arg)
{
    f32 h;
    f32 v;
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C08;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E4BD8, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
    }
    h = ((GameObject*)obj)->anim.currentMoveProgress;
    if (h > lbl_803E4C0C || *(s8*)&((BaddieState*)runtime)->moveDone != 0)
    {
        return 8;
    }
    if (h > lbl_803E4C10)
    {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_BREATH_BURST;
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 5, lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, arg, 0xf0);
    return 0;
}

int DIMbossHitDetect_blueWhiteCapture(int obj, int runtime, f32 arg)
{
    f32 h;
    f32 v;
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C14;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E4BD8, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
    }
    h = ((GameObject*)obj)->anim.currentMoveProgress;
    if (h > lbl_803E4C18)
    {
        gDIMbossSequenceFlags &= ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
    }
    else if (h > lbl_803E4C1C)
    {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0040;
    }
    if (*(int*)&((BaddieState*)runtime)->eventFlags & 1)
    {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY;
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 3, lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, arg, 0xf0);
    return 0;
}

int DIMbossHitDetect_blueWhiteEventCapture(int obj, int runtime, f32 arg)
{
    f32 h;
    f32 v;
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C00;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E4BD8, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
    }
    h = ((GameObject*)obj)->anim.currentMoveProgress;
    if (h > lbl_803E4C18)
    {
        gDIMbossSequenceFlags &= ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
    }
    else if (h > lbl_803E4C20)
    {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0040;
    }
    if (*(int*)&((BaddieState*)runtime)->eventFlags & 0x200)
    {
        gDIMbossSequenceFlags |= (u64)DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY;
        *(int*)&((BaddieState*)runtime)->eventFlags &= ~0x200;
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 3, lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, arg, 0xf0);
    return 0;
}

int DIMbossHitDetect_randomSwipe(int obj, int runtime, f32 arg)
{
    int t;
    f32 v;
    ObjHits_SetHitVolumeSlot(obj, 9, 1, -1);
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
        if ((int)randomGetRange(0, 1) != 0)
        {
            if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 0xb, lbl_803E4BD8, 0);
                ((BaddieState*)runtime)->moveDone = 0;
            }
            ((BaddieState*)runtime)->moveSpeed = lbl_803E4C00;
        }
        else
        {
            if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 0x10, lbl_803E4BD8, 0);
                ((BaddieState*)runtime)->moveDone = 0;
            }
            ((BaddieState*)runtime)->moveSpeed = lbl_803E4C04;
        }
    }
    t = *(int*)&((BaddieState*)runtime)->eventFlags;
    if (t & 0x200)
    {
        *(int*)&((BaddieState*)runtime)->eventFlags = t & ~0x200;
        gDIMbossSequenceFlags |= (DIMBOSS_SEQUENCE_FLAG_0001 | DIMBOSS_SEQUENCE_FLAG_0004);
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(
        obj, runtime, 0, randomGetRange(0, 1), lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, arg, 0xf0);
    return 0;
}

int DIMbossAnim_updatePlayerHitReaction(int obj, int runtime)
{
    u16 local_c;
    s16 local_a;
    u16 local_8;
    int state;
    s16 mode;
    state = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)&((BaddieState*)runtime)->moveDone != 0 || *(s8*)&((BaddieState*)runtime)->moveJustStartedB != 0)
    {
        (*(int (**)(int, int, int, u16*, s16*, u16*))(*(int*)gBaddieControlInterface + 0x14))(
            obj, *(int*)&((BaddieState*)runtime)->targetObj, 0x10, &local_c, &local_a, &local_8);
        ((BaddieState*)runtime)->moveDone = 0;
        if (local_8 < 90)
        {
            if (local_8 > 30 && ((u16)(local_c - 3) <= 1 || local_c == 11 || local_c == 12))
            {
                (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 2);
            }
            else
            {
                (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 9);
            }
        }
        else
        {
            if (local_c == 0 || local_c == 15)
            {
                ((BaddieState*)runtime)->moveDone = 0;
                if (local_8 > 240 && (((u8)(*(u8 (**)(int, int, f32))(*(int*)gBaddieControlInterface + 0x18))(
                    obj, runtime, lbl_803E4BBC)) & 1))
                {
                    (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(
                        obj, runtime, lbl_80325AC8[randomGetRange(0, 5)]);
                }
                else if (((GroundBaddieState*)state)->flags400 & 4)
                {
                    (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(
                        obj, runtime, lbl_803DBF38[randomGetRange(0, 1)]);
                }
                else
                {
                    (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 3);
                }
            }
            else
            {
                (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 2);
            }
        }
    }
    mode = ((BaddieState*)runtime)->controlMode;
    if (mode != 1 && mode != 4 && mode != 5)
    {
        gDIMbossAnimController[0x611] |= 1;
    }
    else
    {
        gDIMbossAnimController[0x611] &= ~1;
    }
    DIM2icicle_updateHitResponse(obj, runtime);
    return 0;
}
