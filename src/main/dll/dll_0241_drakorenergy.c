#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
#include "main/objlib.h"

extern uint GameBit_Get(int eventId);

extern void objRenderFn_8003b8f4(f32);

extern f32 mathSinf(f32 x);

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/anim.h"

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

typedef struct DrakorenergyPlacement
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
    u8 pad1F[0x20 - 0x1F];
    s16 gameBitId;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DrakorenergyPlacement;

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

extern f32 lbl_803E627C;
extern f32 lbl_803E62A0;
extern f32 lbl_803E6278;
extern f32 timeDelta;

undefined4
FUN_80200558(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    DbStealerwormControl* control;

    control = (DbStealerwormControl*)*(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    control->flags14 |= 2;
    control->flags15 |= 4;
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
        control->linkedObj = *(undefined4*)(state + 0x2d0);
        control->unk1C = 0x24;
        control->unk2C = 0;
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                            control->linkedObj, 0x11, obj, 0x12, param_13, param_14, param_15, param_16);
        FUN_80006824(obj, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)obj)->anim.currentMoveProgress)
    {
        control->unk34 = 1;
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
    DbStealerwormControl* control;
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

    control = (DbStealerwormControl*)*(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    control->flags14 |= 2;
    control->flags15 &= 0xfb;
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
            msgQueue = (short*)control->msgStack;
            msgWord48 = 0xe;
            msgWord44 = 1;
            busy = FUN_80006ab8(msgQueue);
            if (busy == 0)
            {
                FUN_80006ac4(msgQueue, (uint) & msgWord48);
            }
            control->unk34 = 1;
        }
    }
    else
    {
        msgQueue = (short*)control->msgStack;
        msgWord30 = 9;
        msgWord2c = 0;
        msgWord28 = 0x24;
        busy = FUN_80006ab8(msgQueue);
        if (busy == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgWord30);
        }
        control->unk34 = 1;
        msgWord34 = *(undefined4*)(state + 0x2d0);
        msgQueue = (short*)control->msgStack;
        msgWord3c = 7;
        msgWord38 = 1;
        busy = FUN_80006ab8(msgQueue);
        if (busy == 0)
        {
            FUN_80006ac4(msgQueue, (uint) & msgWord3c);
        }
        control->unk34 = 1;
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
    DbStealerwormControl* control;
    undefined4 msg;
    undefined4 msgArg;
    undefined4 msgTarget;

    control = (DbStealerwormControl*)*(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(char*)(state + 0x27a) != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        *(undefined4*)(state + 0x2d0) = 0;
        if (control->linkedObj != 0)
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                control->linkedObj, 0x11, obj, 0x10, param_13, param_14, param_15, param_16);
            control->linkedObj = 0;
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
        msgTarget = control->unk30;
        msgArg = control->unk2C;
        hits = (short*)control->msgStack;
        msg = control->unk28;
        busy = FUN_80006ab8(hits);
        if (busy == 0)
        {
            FUN_80006ac4(hits, (uint) & msg);
        }
        control->unk3C = 0;
    }
    *(undefined*)(state + 0x34d) = 0x10;
    *(float*)(state + 0x2a0) = lbl_803E6FD8;
    *(float*)(state + 0x280) = lbl_803E6F40;
    if (*(char*)(state + 0x346) != '\0')
    {
        control->unk34 = 1;
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
    DbStealerwormControl* control;

    extra = *(int*)&((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)*(int*)(extra + 0x40c);
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
        control->unk34 = 1;
    }
    control->flags14 |= 2;
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
                absDy = (double)(((GameObject *)obj)->anim.rootMotionScale - *(float*)(target + 0x10));
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

void FUN_80204320(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

void fn_80204320(int obj);

void DrakorEnergy_func0B_nop(void)
{
}

void drakorenergy_free(void)
{
}

void drakorenergy_hitDetect(void)
{
}

void drakorenergy_release(void)
{
}

void drakorenergy_initialise(void)
{
}

void drakorenergy_init(int* obj, u8* init)
{
    extern uint GameBit_Get(int);
    DrakorEnergyState* sub;
    f32 fz;
    sub = ((GameObject*)obj)->extra;
    sub->mode = 5;
    ((GameObject*)obj)->anim.localPosX = *(f32*)(init + 8);
    ((GameObject*)obj)->anim.localPosY = *(f32*)(init + 0xc);
    ((GameObject*)obj)->anim.localPosZ = *(f32*)(init + 0x10);
    fz = lbl_803E627C;
    ((GameObject*)obj)->anim.velocityZ = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = lbl_803E62A0;
    sub->phase = randomGetRange(0, 0xffff);
    if (GameBit_Get(*(s16*)(init + 0x20)) != 0)
    {
        sub->mode = 4;
    }
}

void dbstealerworm_release(void);

int drakorenergy_getExtraSize(void) { return 0xc; }
int drakorenergy_getObjectTypeId(void) { return 0x0; }
int dbstealerworm_getExtraSize(void);

void drakorenergy_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    DrakorEnergyState* inner = ((GameObject*)obj)->extra;
    u32 t = inner->mode;
    if (t != 0 && t != 4)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E6278);
    }
}

int DrakorEnergy_setScale(int* obj) { return ((DrakorEnergyState*)((int**)obj)[0xb8 / 4])->mode == 0; }

int dbstealerworm_stateHandlerB00(int p1, int p2);

void drakorenergy_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void objMove(int, f32, f32, f32);
    extern f32 Vec_distance(int, int);
    extern f32 Vec_xzDistance(int, int);
    extern void playerAddHealth(int, int);
    extern void Sfx_PlayFromObject(int, int);
    extern f32 mathSinf(f32);
    extern void fn_80221C18(int, f32, f32*, f32*);
    extern void PSVECSubtract(f32*, f32*, f32*);
    extern void PSVECNormalize(f32*, f32*);
    extern void PSVECScale(f32*, f32*, f32);
    extern void objfx_spawnFlaggedTrailBurst(int, f32, int, int, int, int);
    extern f32 timeDelta;
    extern u8 framesThisStep;
    extern f32 lbl_803E627C;
    extern f32 lbl_803E6280;
    extern f32 lbl_803E6284;
    extern f32 lbl_803E6288;
    extern f32 lbl_803E628C;
    extern f32 lbl_803E6290;
    extern f32 lbl_803E6294;
    extern f32 lbl_803DC160;
    extern f32 lbl_803DC164;
    extern f32 lbl_803DC168;
    extern f32 lbl_803DC16C;
    extern int lbl_803DC170;
    extern f32 lbl_803DC174;
    extern s16 lbl_803DC178;
    int blob = *(int*)&((GameObject*)obj)->extra;
    int data;
    int player;
    f32 v;
    f32 dist;
    f32 spd;
    f32 v1[3];
    f32 v2[3];
    s16 trio[12];

    player = Obj_GetPlayerObject();
    data = *(int*)&((GameObject*)obj)->anim.placementData;
    switch (((DrakorEnergyState*)blob)->mode)
    {
    case 0:
        if (GameBit_Get(((DrakorenergyPlacement*)data)->gameBitId) == 1)
        {
            ((DrakorEnergyState*)blob)->mode = 2;
        }
        break;
    case 1:
        if (((DrakorEnergyState*)blob)->startY - ((GameObject*)obj)->anim.localPosY > (v = lbl_803E627C))
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E6280 * -((GameObject*)obj)->anim.velocityY;
            dist = ((GameObject*)obj)->anim.velocityY;
            if (dist >= v)
            {
                dist = ((GameObject*)obj)->anim.velocityY;
            }
            else
            {
                dist = -((GameObject*)obj)->anim.velocityY;
            }
            if (dist < lbl_803E6284)
            {
                ((DrakorEnergyState*)blob)->mode = 2;
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityX = lbl_803E627C;
                break;
            }
        }
        ((GameObject*)obj)->anim.velocityY += lbl_803E6288;
        objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);
        trio[2] = 0xff;
        trio[1] = 0xff - ((DrakorEnergyState*)blob)->phase % 0x500;
        trio[0] = 0xff;
        (*gPartfxInterface)->spawnObject((void*)obj, 0x357, trio, 0, -1, NULL);
        break;
    case 2:
        ((GameObject*)obj)->anim.velocityY = lbl_803DC160 * mathSinf(
            lbl_803E628C * (f32)((DrakorEnergyState*)blob)->phase / lbl_803E6290);
        objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);
        if (Vec_distance(obj + 0x18, player + 0x18) < lbl_803DC164)
        {
            ((DrakorEnergyState*)blob)->mode = 3;
        }
        objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        break;
    case 3:
        dist = Vec_xzDistance(obj + 0x18, player + 0x18);
        if (dist < lbl_803DC168)
        {
            playerAddHealth(player, lbl_803DC170);
            Sfx_PlayFromObject(obj, 0x49);
            ((DrakorEnergyState*)blob)->mode = 4;
        }
        else
        {
            spd = lbl_803DC16C;
            fn_80221C18(player, spd / lbl_803E6294, (f32*)(obj + 0xc), v1);
            PSVECSubtract(v1, (f32*)(obj + 0xc), v2);
            PSVECNormalize(v2, v2);
            if (dist < spd)
            {
                spd = dist;
            }
            PSVECScale(v2, (f32*)(obj + 0x24), spd);
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            trio[2] = 0xff;
            trio[1] = 0;
            trio[0] = 0xff;
            objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        }
        break;
    case 5:
        ((DrakorEnergyState*)blob)->mode = 0;
        break;
    }
    *(s16*)obj += lbl_803DC178;
    ((DrakorEnergyState*)blob)->phase += framesThisStep * 0x500;
}

int dfpseqpoint_SeqFn(int obj, int p2, ObjAnimUpdateState* animUpdate);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
