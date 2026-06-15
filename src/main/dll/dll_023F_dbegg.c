/* DLL 0x023F (dbegg) — DB egg and Dragon Fire Palace objects [0x801FE118-0x801FF884). */
#include "main/game_object.h"
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/objfsa.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
#include "main/dll/anim_internal.h"
#include "main/main.h"
#include "main/objlib.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/anim.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/resource.h"
#include "main/dll/baddie/chuka.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

extern f32 lbl_803E61C8;
extern f32 lbl_803E61D0;
extern int fn_801FE560(int obj, f32* out, f32 a, f32 b, int p3);
extern int Obj_SetActiveModelIndex(int obj, int idx);
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E61CC;
extern int objBboxFn_800640cc(void* from, void* to, f32 radius, int mode, void* hit, int obj, int p7, int p8, int p9,
                              int p10);
extern f32 lbl_803E6218;
extern f32 lbl_803E621C;
extern f32 lbl_803E61E0;
extern f32 lbl_803E61E4;
extern f32 lbl_803E61E8;
extern f32 lbl_803E61EC;
extern f32 lbl_803E61F0;
extern f32 lbl_803E61F4;
extern f32 lbl_803E61F8;
extern f32 lbl_803E61FC;
extern f32 lbl_803E6200;
extern f32 lbl_803E6204;
extern f32 lbl_803E6208;
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 sqrtf(f32 x);
extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int*** listOut, int p6, int p7);
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
extern int ObjHits_GetPriorityHit();
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
extern void Obj_RemoveFromUpdateList(int* obj);
extern u8 lbl_80329514[];
extern f32 timeDelta;
extern u8 gChukaModeTable[9];

void dbegg_processMessages(int obj)
{
    extern int gameBitIncrement(int);
    extern void Obj_RemoveFromUpdateList(int);
    extern void vecRotateZXY(void*, int);
    extern f32 lbl_803E61C8;
    extern f32 lbl_803E61CC;

    AnimBehaviorConfig* config;
    int sub;
    u32 msgType = 0;
    int msgFlag = 0;
    int msgArg;

    sub = *(int*)&((GameObject*)obj)->extra;
    config = (AnimBehaviorConfig*)((GameObject*)obj)->anim.placementData;

    while (ObjMsg_Pop((void*)obj, &msgType, (uint*)&msgArg, (uint*)&msgFlag) != 0)
    {
        if (msgType == 17)
        {
            switch (msgFlag)
            {
            case 18:
                if ((*(u8*)(sub + 0x119) & 0x20) == 0)
                {
                    ObjGroup_RemoveObject(obj, 36);
                }
                ObjHits_DisableObject(obj);
                *(u8*)(sub + 0x118) = 11;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
                break;
            case 17:
                {
                    f32 buf[6];
                    s16* hbuf = (s16*)buf;
                    f32 v;
                    ((GameObject*)obj)->anim.velocityX = *(f32*)(sub + 0x10c);
                    ((GameObject*)obj)->anim.velocityY = *(f32*)(sub + 0x110);
                    ((GameObject*)obj)->anim.velocityZ = -*(f32*)(sub + 0x114);
                    v = lbl_803E61C8;
                    buf[3] = v;
                    buf[4] = v;
                    buf[5] = v;
                    buf[2] = lbl_803E61CC;
                    hbuf[2] = 0;
                    hbuf[1] = 0;
                    hbuf[0] = *(s16*)msgArg;
                    vecRotateZXY(buf, obj + 0x24);
                }
            case 16:
                ObjGroup_AddObject(obj, 36);
            case 20:
                *(u8*)(sub + 0x118) = 5;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8);
                ObjHits_EnableObject(obj);
                break;
            case 19:
                GameBit_Set(config->secondaryConditionId, 1);
                if (config->activationEventId > 0)
                {
                    gameBitIncrement(config->activationEventId);
                }
                Obj_RemoveFromUpdateList(obj);
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
                ObjGroup_RemoveObject(obj, 36);
                break;
            }
        }
    }
}

int dbegg_getExtraSize(void) { return 0x124; }
int dbegg_getObjectTypeId(void) { return 0x8; }

void dbegg_free(int x) { ObjGroup_RemoveObject(x, 0x24); }

void dll_224_update(void* param_1);

#pragma scheduling on
#pragma peephole on
int dbegg_setScale(int obj)
{
    u8* inner = ((GameObject*)obj)->extra;
    return inner[0x118] != 3 ? 1 : 0;
}

#pragma scheduling off
#pragma peephole off
void dbegg_setupFromDef(int obj, u8* state)
{
    AnimBehaviorConfig* config;
    f32 local_unused;

    config = (AnimBehaviorConfig*)((GameObject*)obj)->anim.placementData;
    state[0x119] = 0;
    *(s16*)obj = (s16)(config->facingAngleByte << 8);
    ((GameObject*)obj)->anim.rotY = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
    config->speedScaleByte * lbl_803E61D0;
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    state[0x118] = (u8)(GameBit_Get(config->primaryConditionId) != 0 ? 3 : 1);
    if (state[0x118] == 1)
    {
        if (fn_801FE560(obj, &local_unused, lbl_803E61C8, *(f32*)&lbl_803E61C8, 1) == 0)
        {
            state[0x118] = 2;
        }
    }
    if (config->behaviorMode != 0)
    {
        state[0x119] |= 1;
        if (config->behaviorMode == 2) state[0x119] |= 2;
        if (config->behaviorMode == 3) state[0x118] = 10;
        if (config->behaviorMode == 4)
        {
            state[0x119] |= 4;
            state[0x119] = (u8)(state[0x119] & ~1);
        }
        if (config->behaviorMode == 5)
        {
            state[0x119] |= 8;
            state[0x119] |= 16;
        }
        if (config->behaviorMode == 6)
        {
            Obj_SetActiveModelIndex(obj, 1);
            state[0x119] |= 8;
            state[0x119] |= 16;
        }
        if (config->behaviorMode == 7) state[0x119] |= 32;
    }
    state[0x118] = (u8)(GameBit_Get(config->readyConditionId) != 0 ? 5 : 12);
    if (state[0x118] == 5)
    {
        ObjGroup_AddObject(obj, 36);
    }
    {
        f32 fz = lbl_803E61C8;
        ((GameObject*)obj)->anim.velocityX = fz;
        ((GameObject*)obj)->anim.velocityY = fz;
        ((GameObject*)obj)->anim.velocityZ = fz;
        ((GameObject*)obj)->unkF8 = 0;
        *(f32*)state = fz;
    }
}

#pragma peephole on
int dbegg_func0B(int obj, f32* v)
{
    char* inner = ((GameObject*)obj)->extra;
    if (*(u8*)(inner + 0x118) == 0xb)
    {
        *(f32*)(inner + 0x10c) = v[0];
        *(f32*)(inner + 0x110) = v[1];
        *(f32*)(inner + 0x114) = v[2];
        return 1;
    }
    return 0;
}

#pragma peephole off
void dbegg_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    u8* inner = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        u32 t = inner[0x118];
        if (t != 0xc && t != 4 && t != 0xb)
        {
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E61CC);
        }
    }
}

void dll_224_init(void* obj, void* other);

#pragma peephole on
void dbegg_hitDetect(int obj)
{
    u8* state;
    int hit;
    hit = ObjHits_GetPriorityHit(obj, 0, 0, 0);
    state = ((GameObject*)obj)->extra;
    if (hit == 0x12)
    {
        if (state[0x118] != 4)
        {
            Obj_GetPlayerObject();
        }
    }
    if (state[0x118] != 9)
    {
        void* hitFrom = (void*)&((GameObject*)obj)->anim.previousLocalPosX;
        void* hitTo = (void*)&((GameObject*)obj)->anim.localPosX;
        f32 hitRadius = lbl_803E6218;
        if (objBboxFn_800640cc(hitFrom, hitTo, hitRadius, 1, NULL, obj, 8, -1, 0xff, 0) != 0)
        {
            f32 damping = lbl_803E621C;
            f32 velocityX = ((GameObject*)obj)->anim.velocityX;
            ((GameObject*)obj)->anim.velocityX = velocityX - damping * velocityX;
            velocityX = ((GameObject*)obj)->anim.velocityZ;
            ((GameObject*)obj)->anim.velocityZ = velocityX - damping * velocityX;
        }
    }
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
}

#pragma opt_common_subs off
#pragma opt_loop_invariants off
#pragma peephole off
int fn_801FE560(int obj, f32* out, f32 a, f32 b, int flag)
{
    f32 water;
    f32 ground;
    f32 t;
    f32 u;
    f32 dy;
    int n;
    int i;
    int** list;
    int** cursor;
    int* hit;

    *out = lbl_803E61C8;
    n = hitDetectFn_80065e50(((GameObject*)obj)->anim.localPosX + a, ((GameObject*)obj)->anim.localPosY,
                             ((GameObject*)obj)->anim.localPosZ + b, obj, &list, 0, 0);
    if (n != 0)
    {
        ground = lbl_803E61E0;
        water = ground;
        cursor = list;
        for (i = 0; i < n; i++)
        {
            hit = *cursor;
            dy = *(f32*)hit - ((GameObject*)obj)->anim.localPosY;
            if (*(s8*)((u8*)hit + 0x14) == 0xe)
            {
                if (water >= lbl_803E61C8)
                {
                    t = water;
                }
                else
                {
                    t = -water;
                }
                if (dy >= lbl_803E61C8)
                {
                    u = dy;
                }
                else
                {
                    u = -dy;
                }
                if (u < t)
                {
                    water = dy;
                }
            }
            else
            {
                if (ground >= lbl_803E61C8)
                {
                    t = ground;
                }
                else
                {
                    t = -ground;
                }
                if (dy >= lbl_803E61C8)
                {
                    u = dy;
                }
                else
                {
                    u = -dy;
                }
                if (u < t)
                {
                    ground = dy;
                }
            }
            cursor++;
        }
        if (flag == 0)
        {
            if (lbl_803E61E0 != ground)
            {
                *out = ground;
                return 0;
            }
            if (lbl_803E61E0 != water)
            {
                *out = water;
                return 1;
            }
            *out = lbl_803E61E4;
        }
        else
        {
            if (lbl_803E61E0 != water)
            {
                if (ground >= lbl_803E61C8)
                {
                    t = ground;
                }
                else
                {
                    t = -ground;
                }
                if (water >= lbl_803E61C8)
                {
                    u = water;
                }
                else
                {
                    u = -water;
                }
                if (u <= t || water > lbl_803E61C8)
                {
                    *out = water;
                    return 0;
                }
                *out = ground;
                return 1;
            }
            if (lbl_803E61E0 != ground)
            {
                *out = ground;
                return 1;
            }
            *out = lbl_803E61E4;
        }
    }
    return 0;
}
#pragma opt_loop_invariants reset
#pragma opt_common_subs reset

#pragma peephole on
void fn_801FE774(int cam, f32* vel)
{
    f32 limit;
    f32 force;
    f32 sumX;
    f32 sumZ;
    int count;
    int* objs;
    u8* o;
    int i;

    sumZ = sumX = lbl_803E61C8;
    objs = (int*)ObjGroup_GetObjects(0x14, &count);
    limit = lbl_803E61E8;
    for (i = 0; i < count; i++)
    {
        f32 dy;
        o = (u8*)*objs;
        dy = ((GameObject*)o)->anim.localPosY - *(f32*)(cam + 0x10);
        if (dy <= limit && dy >= lbl_803E61EC)
        {
            f32 dx = ((GameObject*)o)->anim.localPosX - *(f32*)(cam + 0xc);
            f32 dz = ((GameObject*)o)->anim.localPosZ - *(f32*)(cam + 0x14);
            f32 dist = sqrtf(dx * dx + dz * dz);
            f32 radius = lbl_803E61F0 * (f32)(u32) * (u8*)(*(int*)(o + 0x4c) + 0x19);
            if (dist < radius)
            {
                force = (radius - dist) / radius;
                force = force * (lbl_803E61F4 * *(f32*)(o + 8));
                sumX += force * mathSinf((lbl_803E61F8 * (f32)(int) * (s16*)o) / lbl_803E61FC);
                sumZ += force * mathCosf((lbl_803E61F8 * (f32)(int) * (s16*)o) / lbl_803E61FC);
            }
        }
        objs++;
    }
    if (count != 0)
    {
        f32 w;
        f32 m;
        sumX = sumX / (f32)count;
        sumZ = sumZ / (f32)count;
        vel[0] = -(sumX * (w = lbl_803E6200) - vel[0]);
        vel[2] = -(w * sumZ - vel[2]);
        vel[0] = vel[0] * (m = lbl_803E6204);
        vel[2] = vel[2] * m;
        {
            f32 mag = sqrtf(vel[0] * vel[0] + vel[2] * vel[2]);
            if (mag > lbl_803E6208)
            {
                f32 sc = lbl_803E6208 / mag;
                vel[0] = vel[0] * sc;
                vel[2] = vel[2] * sc;
            }
        }
    }
}

/*
 * DbStealerwormControl - the per-family control record hung off
 * GroundBaddieState.control (state+0x40C) for dbstealerworm
 * (extraSize 0x460 = GroundBaddieState 0x410 + a 0x50 private tail;
 * the control record itself is memset(0x50) in dbstealerworm_init).
 */

/* chuka extra block (extraSize 0xC). */

typedef struct DbeggPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 targetPosX;
    f32 targetPosY;
    f32 targetPosZ;
    u32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 triggerGameBit;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DbeggPlacement;

undefined4
#pragma peephole off
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

void dbegg_release(void)
{
}

void dbegg_initialise(void)
{
}

void GCRobotBlast_free(void);

void dbegg_init(int obj)
{
    extern void dbegg_setupFromDef(int obj, int* state); /* #57 */
    extern undefined4 ObjMsg_AllocQueue(); /* #57 */
    ObjModelState* modelState;
    dbegg_setupFromDef(obj, ((GameObject*)obj)->extra);
    ObjMsg_AllocQueue(obj, 8);
    modelState = ((GameObject*)obj)->anim.modelState;
    if (modelState != NULL)
    {
        modelState->flags |= 0x4008;
    }
}

void DFP_Torch_free(int obj);

void dbegg_update(int obj)
{
    extern void dbegg_setupFromDef(int obj, int* state); /* #57 */
    extern int Obj_GetPlayerObject(void);
    extern int objPosToMapBlockIdx(f32, f32, f32);
    extern void dbegg_processMessages(int);
    extern int fn_801FE560(int, f32*, f32, f32, int);
    extern void fn_801FE774(int, f32*);
    extern void objMove(int, f32, f32, f32);
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_KeepAliveLoopedObjectSound(int, int);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern int randomGetRange(int, int);
    extern f32 Vec_xzDistance(int, int);
    extern void ObjGroup_RemoveObject(int, int);
    extern void ObjGroup_AddObject(int, int);
    extern void ObjMsg_SendToObject(int, int, int, int);
    extern uint getButtonsJustPressed(int);
    extern f32 sqrtf(f32);
    extern void Vec3_Normalize(int);
    extern f32 PSVECMag(int);
    extern void fn_80137948(char*, ...);
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_DisableObject(int);
    extern f32 timeDelta;
    extern f32 oneOverTimeDelta;
    extern char sAnimGreaterMessage[];
    extern int lbl_803E61C0;
    extern int lbl_803E61C4;
    extern f32 lbl_803E61C8;
    extern f32 lbl_803E61CC;
    extern f32 lbl_803E61E4;
    extern f32 lbl_803E61EC;
    extern f32 lbl_803E6200;
    extern f32 lbl_803E6220;
    extern f32 lbl_803E6224;
    extern f32 lbl_803E6228;
    extern f32 lbl_803E622C;
    extern f32 lbl_803E6230;
    extern f32 lbl_803E6234;
    extern f32 lbl_803E6238;
    extern f32 lbl_803E623C;
    extern f32 lbl_803E6240;
    extern f32 lbl_803E6244;
    extern f32 lbl_803E6248;
    extern f32 lbl_803E624C;
    extern f32 lbl_803E6250;
    extern f32 lbl_803E6254;
    extern f32 lbl_803E6258;
    extern f32 lbl_803E625C;
    extern f32 lbl_803E6260;
    extern f32 lbl_803E6264;
    extern f32 lbl_803E6268;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    int player;
    int blob;
    int p2;
    int b2;
    int d2;
    int n;
    int i;
    f32 v;
    f32 fx;
    f32 fz;
    f32 b3[3];
    f32 d[3];
    int buf2[2];
    f32 h;

    player = Obj_GetPlayerObject();
    blob = *(int*)&((GameObject*)obj)->extra;
    n = lbl_803E61C0;
    i = lbl_803E61C4;
    buf2[1] = i;
    buf2[0] = n;
    if (objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                            ((GameObject*)obj)->anim.localPosZ) != -1)
    {
        dbegg_processMessages(obj);
        hitState->flags &= ~0x400;
        switch (((DbEggState*)blob)->mode)
        {
        case 5:
            if (((GameObject*)obj)->unkF8 == 0)
            {
                hitState->flags |= 1;
            }
            if (fn_801FE560(obj, &h, lbl_803E61C8, *(f32*)&lbl_803E61C8, 1) == 0)
            {
                ((DbEggState*)blob)->mode = 2;
                break;
            }
            v = h;
            v = v >= lbl_803E61C8 ? v : -v;
            if (v < lbl_803E6220)
            {
                if (((DbEggState*)blob)->flags119 & 0x10)
                {
                    ((DbEggState*)blob)->mode = 0xd;
                }
                else
                {
                    ((DbEggState*)blob)->mode = 1;
                }
                fz = lbl_803E61C8;
                ((GameObject*)obj)->anim.velocityX = lbl_803E61C8;
                ((GameObject*)obj)->anim.velocityZ = fz;
                ((GameObject*)obj)->anim.velocityY = fz;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + h;
            }
            else
            {
                ((GameObject*)obj)->anim.velocityY += lbl_803E6224;
                if (h > lbl_803E61C8)
                {
                    ((GameObject*)obj)->anim.velocityY = lbl_803E6228 * -((GameObject*)obj)->anim.velocityY;
                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * lbl_803E622C;
                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * lbl_803E622C;
                    v = ((GameObject*)obj)->anim.velocityY;
                    v = v >= lbl_803E61C8 ? v : -v;
                    if (v > lbl_803E6230)
                    {
                        Sfx_PlayFromObject(obj, 0x2df);
                    }
                }
                objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                        ((GameObject*)obj)->anim.velocityY * timeDelta, ((GameObject*)obj)->anim.velocityZ * timeDelta);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
            break;
        case 1:
            if (((GameObject*)obj)->unkF8 == 0)
            {
                hitState->flags |= 1;
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
            break;
        case 2:
            if (((DbEggState*)blob)->flags119 & 4)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + (((DbeggPlacement*)data)->
                    targetPosX - ((GameObject*)obj)->anim.localPosX) / (fz = lbl_803E61E4);
                ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + (((DbeggPlacement*)data)->
                    targetPosY - ((GameObject*)obj)->anim.localPosY) / fz;
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + (((DbeggPlacement*)data)->
                    targetPosZ - ((GameObject*)obj)->anim.localPosZ) / fz;
                if (GameBit_Get(0x44d) != 0)
                {
                    ((DbEggState*)blob)->mode = 0xa;
                }
            }
            hitState->flags |= 0x400;
            fz = lbl_803E61C8;
            b3[0] = lbl_803E61C8;
            b3[1] = fz;
            b3[2] = fz;
            fn_801FE774(obj, b3);
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + b3[0];
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + b3[1];
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + b3[2];
            if (fn_801FE560(obj, &h, ((GameObject*)obj)->anim.velocityX * timeDelta,
                            ((GameObject*)obj)->anim.velocityZ * timeDelta, 1) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = lbl_803E6234 * ((GameObject*)obj)->anim.velocityX;
                ((GameObject*)obj)->anim.velocityZ = lbl_803E6234 * ((GameObject*)obj)->anim.velocityZ;
                fn_801FE560(obj, &h, ((GameObject*)obj)->anim.velocityX * timeDelta,
                            ((GameObject*)obj)->anim.velocityZ * timeDelta, 1);
            }
            h = h + ((DbEggState*)blob)->waterOffset;
            if (oneOverTimeDelta != lbl_803E61C8)
            {
                ((GameObject*)obj)->anim.velocityY = h * (lbl_803E6238 * oneOverTimeDelta);
            }
            else
            {
                ((GameObject*)obj)->anim.velocityY = lbl_803E61C8;
            }
            randomGetRange(0x64, 0x1388);
            randomGetRange(0x64, 0x1388);
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            if (randomGetRange(0, 10) == 0)
            {
                int nb = h < lbl_803E6200;
                nb = (nb < 0) ? -nb : nb;
                if (nb != 0)
                {
                    ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                        ((GameObject*)obj)->anim.localPosX,
                        ((GameObject*)obj)->anim.localPosY - ((DbEggState*)blob)->waterOffset,
                        ((GameObject*)obj)->anim.localPosZ, *(s16*)obj, (f32)randomGetRange(1, 10), 1);
                }
            }
            if (GameBit_Get(0x426) != 0)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                ((DbEggState*)blob)->waterOffset = ((DbEggState*)blob)->waterOffset - lbl_803E623C * timeDelta;
                if (((DbEggState*)blob)->waterOffset < lbl_803E61EC)
                {
                    GameBit_Set(0x428, GameBit_Get(0x428) + 1);
                    ((DbEggState*)blob)->mode = 7;
                    fz = lbl_803E61C8;
                    ((GameObject*)obj)->anim.velocityY = lbl_803E61C8;
                    ((GameObject*)obj)->anim.velocityX = fz;
                    ((GameObject*)obj)->anim.velocityZ = fz;
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                }
            }
            else if (((DbEggState*)blob)->flags119 & 2)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
            break;
        case 4:
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            break;
        case 6:
            if (Vec_xzDistance(obj + 0x18, data + 8) > lbl_803E6240 && (((DbEggState*)blob)->flags119 & 2) == 0)
            {
                p2 = Obj_GetPlayerObject();
                b2 = *(int*)&((GameObject*)obj)->extra;
                d2 = *(int*)&((GameObject*)obj)->anim.placementData;
                ObjGroup_RemoveObject(obj, 0x24);
                ((DbEggState*)b2)->mode = 3;
                GameBit_Set(0x3c4, 1);
                GameBit_Set(0x86d, 1);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                GameBit_Set(((DbeggPlacement*)d2)->triggerGameBit, 1);
                ((DbEggState*)b2)->msg11C = -1;
                ((DbEggState*)b2)->msg11E = 0;
                ((DbEggState*)b2)->msg120 = lbl_803E61CC;
                ObjMsg_SendToObject(p2, 0x7000a, obj, b2 + 0x11c);
                ((GameObject*)obj)->unkF8 = 0;
            }
            else if (getButtonsJustPressed(0) & 0x100)
            {
                ((DbEggState*)blob)->mode = 5;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
            }
            else
            {
                hitState->flags &= ~1;
                ObjMsg_SendToObject(player, 0x100008, obj, 0x38000);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
            break;
        case 0xb:
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            return;
        case 7:
            fn_801FE560(obj, &h, lbl_803E61C8, *(f32*)&lbl_803E61C8, 0);
            v = h;
            v = v >= lbl_803E61C8 ? v : -v;
            if (v < lbl_803E6220)
            {
                ((DbEggState*)blob)->mode = 8;
                fz = lbl_803E61C8;
                ((GameObject*)obj)->anim.velocityX = lbl_803E61C8;
                ((GameObject*)obj)->anim.velocityZ = fz;
            }
            else
            {
                ((GameObject*)obj)->anim.velocityY += lbl_803E6244;
                if (h > lbl_803E61C8)
                {
                    ((GameObject*)obj)->anim.velocityY = lbl_803E6248 * -((GameObject*)obj)->anim.velocityY;
                }
                objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                        ((GameObject*)obj)->anim.velocityY * timeDelta, ((GameObject*)obj)->anim.velocityZ * timeDelta);
            }
            break;
        case 8:
            if (GameBit_Get(0x42a) != 0)
            {
                dbegg_setupFromDef(obj, (int*)blob);
            }
            else if (randomGetRange(0, 10) == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x3be, NULL, 0, -1, NULL);
            }
            break;
        case 0xa:
            if ((*gRomCurveInterface)->initCurve(&((DbEggState*)blob)->curve, (void*)obj, lbl_803E624C,
                                                 buf2, 2) != 0)
            {
                ((DbEggState*)blob)->mode = 5;
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                ((DbEggState*)blob)->mode = 9;
                n = ((DbEggState*)blob)->flags119;
                if (n & 4)
                {
                    ((DbEggState*)blob)->flags119 = n & ~4;
                }
            }
            break;
        case 9:
            if (Curve_AdvanceAlongPath(&((DbEggState*)blob)->curve, lbl_803E6250) != 0 ||
                ((DbEggState*)blob)->curve.atSegmentEnd != 0)
            {
                if ((*gRomCurveInterface)->goNextPoint(&((DbEggState*)blob)->curve) != 0)
                {
                    ((DbEggState*)blob)->mode = 5;
                }
            }
            else
            {
                ((GameObject*)obj)->anim.velocityX = ((DbEggState*)blob)->curve.posX - ((GameObject*)obj)->anim.
                    localPosX;
                ((GameObject*)obj)->anim.velocityY = ((DbEggState*)blob)->curve.posY - ((GameObject*)obj)->anim.
                    localPosY;
                ((GameObject*)obj)->anim.velocityZ = ((DbEggState*)blob)->curve.posZ - ((GameObject*)obj)->anim.
                    localPosZ;
                fx = sqrtf(
                    ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ + (((GameObject*)obj)->anim.
                        velocityX * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.velocityY * ((
                            GameObject*)obj)->anim.velocityY));
                if (fx > lbl_803E6254 * timeDelta)
                {
                    Vec3_Normalize(obj + 0x24);
                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (lbl_803E6254 *
                        timeDelta);
                    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * (lbl_803E6254 *
                        timeDelta);
                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * (lbl_803E6254 *
                        timeDelta);
                    fn_80137948(sAnimGreaterMessage);
                }
                ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + ((GameObject*)obj)->anim.
                    velocityX;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + ((GameObject*)obj)->anim.
                    velocityY;
                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + ((GameObject*)obj)->anim.
                    velocityZ;
            }
            break;
        case 0xc:
            if (GameBit_Get(((DbeggPlacement*)data)->unk24) != 0)
            {
                ObjGroup_AddObject(obj, 0x24);
                ((DbEggState*)blob)->mode = 5;
            }
            break;
        case 0xd:
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + (((DbeggPlacement*)data)->
                targetPosX - ((GameObject*)obj)->anim.localPosX) / (fz = lbl_803E6258);
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + (((DbeggPlacement*)data)->
                targetPosY - ((GameObject*)obj)->anim.localPosY) / fz;
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + (((DbeggPlacement*)data)->
                targetPosZ - ((GameObject*)obj)->anim.localPosZ) / fz;
            d[0] = ((GameObject*)obj)->anim.localPosX - ((DbeggPlacement*)data)->targetPosX;
            d[1] = ((GameObject*)obj)->anim.localPosY - ((DbeggPlacement*)data)->targetPosY;
            d[2] = ((GameObject*)obj)->anim.localPosZ - ((DbeggPlacement*)data)->targetPosZ;
            Sfx_KeepAliveLoopedObjectSound(obj, 0x442);
            fz = *(f32*)((int)d + 8);
            fz = fz >= lbl_803E61C8 ? fz : -fz;
            fx = *(f32*)((int)d + 0);
            fx = fx >= lbl_803E61C8 ? fx : -fx;
            if (fx + fz < lbl_803E625C)
            {
                ObjHits_EnableObject(obj);
                ((DbEggState*)blob)->mode = 1;
                ((GameObject*)obj)->anim.localPosX = ((DbeggPlacement*)data)->targetPosX;
                ((GameObject*)obj)->anim.localPosY = ((DbeggPlacement*)data)->targetPosY;
                ((GameObject*)obj)->anim.localPosZ = ((DbeggPlacement*)data)->targetPosZ;
            }
            else
            {
                n = (int)(PSVECMag(obj + 0x24) / lbl_803E6260);
                for (i = 0; i < n; i++)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x345, NULL, 1, -1, NULL);
                }
                objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                        ((GameObject*)obj)->anim.velocityY * timeDelta, ((GameObject*)obj)->anim.velocityZ * timeDelta);
            }
            break;
        }
        if (((DbEggState*)blob)->flags119 & 8)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            ObjHits_DisableObject(obj);
            if (GameBit_Get(((DbeggPlacement*)data)->triggerGameBit) != 0)
            {
                ((DbEggState*)blob)->flags119 &= ~9;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                ObjHits_EnableObject(obj);
            }
        }
        else if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1)
        {
            if (GameBit_Get(0x3c4) == 0)
            {
                if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E6264)
                {
                    if ((((DbEggState*)blob)->flags119 & 1) == 0)
                    {
                        p2 = Obj_GetPlayerObject();
                        b2 = *(int*)&((GameObject*)obj)->extra;
                        d2 = *(int*)&((GameObject*)obj)->anim.placementData;
                        ObjGroup_RemoveObject(obj, 0x24);
                        ((DbEggState*)b2)->mode = 3;
                        GameBit_Set(0x3c4, 1);
                        GameBit_Set(0x86d, 1);
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                        GameBit_Set(((DbeggPlacement*)d2)->triggerGameBit, 1);
                        ((DbEggState*)b2)->msg11C = -1;
                        ((DbEggState*)b2)->msg11E = 0;
                        ((DbEggState*)b2)->msg120 = lbl_803E61CC;
                        ObjMsg_SendToObject(p2, 0x7000a, obj, b2 + 0x11c);
                    }
                    else
                    {
                        v = ((GameObject*)obj)->anim.localPosY - *(f32*)(player + 0x10);
                        v = v >= lbl_803E61C8 ? v : -v;
                        if (v < lbl_803E6268)
                        {
                            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                            ((DbEggState*)blob)->mode = 6;
                            hitState->flags &= ~1;
                        }
                    }
                }
            }
        }
    }
}

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
