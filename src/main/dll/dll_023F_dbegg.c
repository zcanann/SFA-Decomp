/*
 * DLL 0x023F (dbegg) - the "dbegg" floating egg object [0x801FE118-0x801FF884).
 *
 * A buoyant egg driven by a mode state machine (DbEggState.mode, byte at
 * +0x118; flags119 at +0x119). dbegg_update dispatches per mode:
 *   1  settled/idle            2  drifting on water (flocking + buoyancy)
 *   4  inert                   5  falling, seeking water/ground surface
 *   6  player-pickup prompt    7  sinking after release
 *   8  respawn wait            9  curve-follow path
 *   0xa curve init             0xb held (velocity from message +0x10c..)
 *   0xc gated respawn          0xd homing-to-target reposition
 * Surface probing (water tri type 0xe vs ground) is fn_801FE560; sibling-egg
 * flocking repulsion is fn_801FE774. Buoyancy/clamp/turn constants live in
 * the lbl_803E61xx/.. pool. dbegg_setupFromDef seeds mode from the placement
 * config's primary/ready condition game bits; behaviorMode selects variant
 * flags119 bits (held, curve, model-1, group-32).
 *
 * Game bits: 0x3c4 (egg grabbed, global gate), 0x86d, 0x426/0x428 (sink
 * progress + count), 0x42a (respawn), 0x44d, and the placement's
 * triggerGameBit. Messages are pumped by dbegg_processMessages (ObjMsg type
 * 17; subtypes 16-20).
 *
 * FUN_80200558 is a dbstealerworm sequence handler that genuinely lands in
 * this object's pool; the remaining FUN_ drift duplicates of the
 * 0x80200740-0x80204320 sibling handlers were dead and removed.
 */
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
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
#include "main/objlib.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/anim.h"
#include "main/gamebits.h"
#include "main/pad.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#define PAD_BUTTON_A 0x100
extern const f32 lbl_803E61C8;
extern const f32 gDbEggSpeedByteScale;
extern int fn_801FE560(int obj, f32* out, f32 a, f32 b, int p3);
extern int Obj_SetActiveModelIndex(int obj, int idx);
extern void objRenderFn_8003b8f4(int* obj);
extern const f32 lbl_803E61CC;
extern int objBboxFn_800640cc(void* from, void* to, f32 radius, int mode, void* hit, int obj, int p7, int p8, int p9,
                              int p10);
extern const f32 lbl_803E6218;
extern const f32 lbl_803E621C;
extern const f32 gDbEggSurfaceNotFound;
extern const f32 lbl_803E61E4;
extern const f32 lbl_803E61E8;
extern const f32 lbl_803E61EC;
extern const f32 lbl_803E61F0;
extern const f32 lbl_803E61F4;
extern const f32 gDbEggPi;
extern const f32 gDbEggAngleHalfPeriod;
extern const f32 lbl_803E6200;
extern const f32 lbl_803E6204;
extern const f32 lbl_803E6208;
extern float mathSinf(float x);
extern float mathCosf(float x);
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

typedef enum DbEggMode
{
    DBEGG_MODE_SETTLED = 1,        /* settled / idle on the surface */
    DBEGG_MODE_DRIFTING = 2,       /* drifting on water: flocking + buoyancy */
    DBEGG_MODE_RELEASED = 3,       /* released / inactive (no longer updated) */
    DBEGG_MODE_INERT = 4,          /* inert (hitbox suppressed) */
    DBEGG_MODE_FALLING = 5,        /* falling, seeking the water/ground surface */
    DBEGG_MODE_PICKUP_PROMPT = 6,  /* offering the player a pickup prompt */
    DBEGG_MODE_SINKING = 7,        /* sinking after release */
    DBEGG_MODE_RESPAWN_WAIT = 8,   /* waiting to respawn */
    DBEGG_MODE_CURVE_FOLLOW = 9,   /* following a rom-curve path */
    DBEGG_MODE_CURVE_INIT = 0xA,   /* initialising the curve walker */
    DBEGG_MODE_HELD = 0xB,         /* held; velocity driven from the carry message */
    DBEGG_MODE_GATED_RESPAWN = 0xC, /* respawn gated on the activate game bit */
    DBEGG_MODE_HOMING = 0xD,       /* homing back to its target reposition point */
} DbEggMode;
extern u32 FUN_80006824();
extern int randomGetRange(int lo, int hi);
extern u64 FUN_800305f8();
extern u32 ObjMsg_SendToObject();
extern f32 lbl_803E6F40;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern void Obj_RemoveFromUpdateList(int obj);
extern f32 timeDelta;

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
    s16 activateGameBit;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DbeggPlacement;

#pragma optimization_level 2
void dbegg_processMessages(int obj)
{
    extern int gameBitIncrement(int bit);
    extern void Obj_RemoveFromUpdateList(int);
    extern void vecRotateZXY(void*, int);
    extern const f32 lbl_803E61C8;
    extern const f32 lbl_803E61CC;

    int sub;
    AnimBehaviorConfig* config;
    u32 msgType = 0;
    int msgFlag = 0;
    int msgArg;

    sub = *(int*)&((GameObject*)obj)->extra;
    config = (AnimBehaviorConfig*)((GameObject*)obj)->anim.placementData;

    while ((int)ObjMsg_Pop((void*)obj, &msgType, (u32*)&msgArg, (u32*)&msgFlag) != 0)
    {
        if (msgType == 17)
        {
            switch (msgFlag)
            {
            case 18:
                if ((((DbEggState*)sub)->flags119 & 0x20) == 0)
                {
                    ObjGroup_RemoveObject(obj, 36);
                }
                ObjHits_DisableObject(obj);
                ((DbEggState*)sub)->mode = DBEGG_MODE_HELD;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
                break;
            case 17:
                {
                    f32 buf[6];
                    f32 v;
                    ((GameObject*)obj)->anim.velocityX = ((DbEggState*)sub)->launchVelX;
                    ((GameObject*)obj)->anim.velocityY = ((DbEggState*)sub)->launchVelY;
                    ((GameObject*)obj)->anim.velocityZ = -((DbEggState*)sub)->launchVelZ;
                    v = lbl_803E61C8;
                    buf[3] = v;
                    buf[4] = v;
                    buf[5] = v;
                    buf[2] = lbl_803E61CC;
                    ((s16*)buf)[2] = 0;
                    ((s16*)buf)[1] = 0;
                    ((s16*)buf)[0] = *(s16*)msgArg;
                    vecRotateZXY(buf, obj + 0x24);
                }
            case 16:
                ObjGroup_AddObject(obj, 36);
            case 20:
                ((DbEggState*)sub)->mode = DBEGG_MODE_FALLING;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
                ObjHits_EnableObject(obj);
                break;
            case 19:
                GameBit_Set(config->secondaryConditionId, 1);
                if ((int)config->activationEventId > 0)
                {
                    gameBitIncrement((int)config->activationEventId);
                }
                Obj_RemoveFromUpdateList(obj);
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
                ObjGroup_RemoveObject(obj, 36);
                break;
            }
        }
    }
}
#pragma optimization_level reset

int dbegg_getExtraSize(void) { return 0x124; }
int dbegg_getObjectTypeId(void) { return 0x8; }

void dbegg_free(int x) { ObjGroup_RemoveObject(x, 0x24); }

#pragma scheduling on
#pragma peephole on
int dbegg_setScale(int obj)
{
    u8* inner = ((GameObject*)obj)->extra;
    return ((DbEggState*)inner)->mode != DBEGG_MODE_RELEASED ? 1 : 0;
}

#pragma scheduling off
#pragma peephole off
void dbegg_setupFromDef(int obj, u8* state)
{
    AnimBehaviorConfig* config;
    f32 surfaceProbeOut;

    config = (AnimBehaviorConfig*)((GameObject*)obj)->anim.placementData;
    state[0x119] = 0;
    ((GameObject*)obj)->anim.rotX = (s16)(config->facingAngleByte << 8);
    ((GameObject*)obj)->anim.rotY = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
    config->speedScaleByte * gDbEggSpeedByteScale;
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    state[0x118] = (u8)(GameBit_Get(config->primaryConditionId) != 0 ? 3 : 1);
    if (state[0x118] == 1)
    {
        if (fn_801FE560(obj, &surfaceProbeOut, lbl_803E61C8, *(f32*)&lbl_803E61C8, 1) == 0)
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
    u8* inner = ((GameObject*)obj)->extra;
    if (((DbEggState*)inner)->mode == 0xb)
    {
        ((DbEggState*)inner)->launchVelX = v[0];
        ((DbEggState*)inner)->launchVelY = v[1];
        ((DbEggState*)inner)->launchVelZ = v[2];
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
        u32 t = ((DbEggState*)inner)->mode;
        if (t != 0xc && t != 4 && t != 0xb)
        {
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E61CC);
        }
    }
}

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
        void* hitFrom = &((GameObject*)obj)->anim.previousLocalPosX;
        void* hitTo = &((GameObject*)obj)->anim.localPosX;
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
    f32 bestAbs;
    f32 curAbs;
    f32 dy;
    int hitCount;
    int i;
    int** hitList;
    int** hitCursor;
    int* hitTri;

    *out = lbl_803E61C8;
    hitCount = hitDetectFn_80065e50(((GameObject*)obj)->anim.localPosX + a, ((GameObject*)obj)->anim.localPosY,
                             ((GameObject*)obj)->anim.localPosZ + b, obj, &hitList, 0, 0);
    if (hitCount != 0)
    {
        ground = gDbEggSurfaceNotFound;
        water = ground;
        hitCursor = hitList;
        for (i = 0; i < hitCount; i++)
        {
            hitTri = *hitCursor;
            dy = *(f32*)hitTri - ((GameObject*)obj)->anim.localPosY;
            if (*(s8*)((u8*)hitTri + 0x14) == 0xe)
            {
                if (water >= lbl_803E61C8)
                {
                    bestAbs = water;
                }
                else
                {
                    bestAbs = -water;
                }
                if (dy >= lbl_803E61C8)
                {
                    curAbs = dy;
                }
                else
                {
                    curAbs = -dy;
                }
                if (curAbs < bestAbs)
                {
                    water = dy;
                }
            }
            else
            {
                if (ground >= lbl_803E61C8)
                {
                    bestAbs = ground;
                }
                else
                {
                    bestAbs = -ground;
                }
                if (dy >= lbl_803E61C8)
                {
                    curAbs = dy;
                }
                else
                {
                    curAbs = -dy;
                }
                if (curAbs < bestAbs)
                {
                    ground = dy;
                }
            }
            hitCursor++;
        }
        if (flag == 0)
        {
            if (gDbEggSurfaceNotFound != ground)
            {
                *out = ground;
                return 0;
            }
            if (gDbEggSurfaceNotFound != water)
            {
                *out = water;
                return 1;
            }
            *out = lbl_803E61E4;
        }
        else
        {
            if (gDbEggSurfaceNotFound != water)
            {
                if (ground >= lbl_803E61C8)
                {
                    bestAbs = ground;
                }
                else
                {
                    bestAbs = -ground;
                }
                if (water >= lbl_803E61C8)
                {
                    curAbs = water;
                }
                else
                {
                    curAbs = -water;
                }
                if (curAbs <= bestAbs || water > lbl_803E61C8)
                {
                    *out = water;
                    return 0;
                }
                *out = ground;
                return 1;
            }
            if (gDbEggSurfaceNotFound != ground)
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
void fn_801FE774(int obj, f32* vel)
{
    f32 limit;
    f32 force;
    f32 sumX;
    f32 sumZ;
    int count;
    int* objCursor;
    u8* sibling;
    int i;

    int* objList;
    sumZ = sumX = lbl_803E61C8;
    objList = (int*)ObjGroup_GetObjects(0x14, &count);
    for (i = 0, objCursor = objList, limit = lbl_803E61E8; i < count; i++)
    {
        f32 dy;
        sibling = (u8*)*objCursor;
        dy = ((GameObject*)sibling)->anim.localPosY - *(f32*)(obj + 0x10);
        if (dy <= limit && dy >= lbl_803E61EC)
        {
            f32 dx = ((GameObject*)sibling)->anim.localPosX - *(f32*)(obj + 0xc);
            f32 dz = ((GameObject*)sibling)->anim.localPosZ - *(f32*)(obj + 0x14);
            f32 dist = sqrtf(dx * dx + dz * dz);
            f32 radius = lbl_803E61F0 * (f32)(u32) * (u8*)(*(int*)(sibling + 0x4c) + 0x19);
            if (dist < radius)
            {
                force = (radius - dist) / radius;
                force = force * (lbl_803E61F4 * *(f32*)(sibling + 8));
                sumX += force * mathSinf((gDbEggPi * (f32)(int) * (s16*)sibling) / gDbEggAngleHalfPeriod);
                sumZ += force * mathCosf((gDbEggPi * (f32)(int) * (s16*)sibling) / gDbEggAngleHalfPeriod);
            }
        }
        objCursor++;
    }
    if (count != 0)
    {
        f32 w;
        f32 m;
        sumX = sumX / count;
        sumZ = sumZ / count;
        w = lbl_803E6200;
        vel[0] = -(w * sumX - vel[0]);
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

u32
#pragma peephole off
FUN_80200558(u64 arg1, double arg2, double arg3, u64 arg4, u64 arg5,
             u64 arg6, u64 arg7, u64 arg8, u32 obj, int state,
             u32 arg11, u32 arg12, u32 arg13, u32 arg14,
             u32 arg15, u32 arg16)
{
    int control;

    control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    ((DbStealerwormControl*)control)->flags14 |= 2;
    ((DbStealerwormControl*)control)->flags15 |= 4;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E6F80;
    if (*(char*)(state + 0x27a) != '\0')
    {
        arg1 = FUN_800305f8((double)lbl_803E6F40, arg2, arg3, arg4, arg5, arg6, arg7,
                               arg8, obj, 0x11, 0, arg12, arg13, arg14, arg15, arg16);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 0x1f;
    if (*(char*)(state + 0x27a) != '\0')
    {
        ((DbStealerwormControl*)control)->linkedObj = *(u32*)&((GroundBaddieState*)state)->baddie.targetObj;
        ((DbStealerwormControl*)control)->unk1C = 0x24;
        ((DbStealerwormControl*)control)->unk2C = 0;
        ObjMsg_SendToObject(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                            ((DbStealerwormControl*)control)->linkedObj, 0x11, obj, 0x12, arg13, arg14, arg15, arg16);
        FUN_80006824(obj, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)obj)->anim.currentMoveProgress)
    {
        ((DbStealerwormControl*)control)->unk34 = 1;
    }
    return 0;
}

void dbegg_release(void)
{
}

void dbegg_initialise(void)
{
}

void dbegg_init(int obj)
{
    extern void dbegg_setupFromDef(int obj, int* state);
    extern u32 ObjMsg_AllocQueue();
    ObjModelState* modelState;
    dbegg_setupFromDef(obj, ((GameObject*)obj)->extra);
    ObjMsg_AllocQueue(obj, 8);
    modelState = ((GameObject*)obj)->anim.modelState;
    if (modelState != NULL)
    {
        modelState->flags |= 0x4008;
    }
}

typedef struct DbEggIntPair
{
    s32 a;
    s32 b;
} DbEggIntPair;

void dbegg_update(int obj)
{
    extern void dbegg_setupFromDef(int obj, int* state);
    extern int Obj_GetPlayerObject(void);
    extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
    extern void dbegg_processMessages(int);
    extern int fn_801FE560(int, f32*, f32, f32, int);
    extern void fn_801FE774(int, f32*);
    extern void objMove(int, f32, f32, f32);

    extern void Sfx_KeepAliveLoopedObjectSound(int, int);
    extern f32 Vec_xzDistance(int, int);
    extern void Vec3_Normalize(int);
    extern f32 PSVECMag(int);
    extern void fn_80137948(char* fmt, ...);
    extern void ObjHits_EnableObject(int);
    extern f32 oneOverTimeDelta;
    extern char sAnimGreaterMessage[];
    extern int lbl_803E61C0;
    extern const f32 lbl_803E61C8;
    extern const f32 lbl_803E61CC;
    extern const f32 lbl_803E61E4;
    extern const f32 lbl_803E61EC;
    extern const f32 lbl_803E6200;
    extern const f32 lbl_803E6220;
    extern const f32 lbl_803E6224;
    extern const f32 lbl_803E6228;
    extern const f32 lbl_803E622C;
    extern const f32 lbl_803E6230;
    extern const f32 lbl_803E6234;
    extern const f32 lbl_803E6238;
    extern const f32 lbl_803E623C;
    extern const f32 lbl_803E6240;
    extern const f32 lbl_803E6244;
    extern const f32 lbl_803E6248;
    extern const f32 lbl_803E624C;
    extern const f32 lbl_803E6250;
    extern const f32 lbl_803E6254;
    extern const f32 lbl_803E6258;
    extern const f32 lbl_803E625C;
    extern const f32 lbl_803E6260;
    extern const f32 lbl_803E6264;
    extern const f32 lbl_803E6268;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
#define hitState ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)
    int player;
    int eggState;
    int d2;
    int b2;
    int i;
    int n;
    int playerObj;
    f32 v;
    f32 fx;
    f32 fz;
    f32 flockVel[3];
    f32 d[3];
    int curvePair[2];
    f32 h;

    player = Obj_GetPlayerObject();
    eggState = *(int*)&((GameObject*)obj)->extra;
    *(DbEggIntPair*)curvePair = *(DbEggIntPair*)&lbl_803E61C0;
    if (objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                            ((GameObject*)obj)->anim.localPosZ) != -1)
    {
        dbegg_processMessages(obj);
        hitState->flags &= ~0x400;
        switch (((DbEggState*)eggState)->mode)
        {
        case DBEGG_MODE_FALLING:
            if (((GameObject*)obj)->unkF8 == 0)
            {
                hitState->flags |= 1;
            }
            if (fn_801FE560(obj, &h, lbl_803E61C8, *(f32*)&lbl_803E61C8, 1) == 0)
            {
                ((DbEggState*)eggState)->mode = DBEGG_MODE_DRIFTING;
                break;
            }
            v = h;
            v = v >= lbl_803E61C8 ? v : -v;
            if (v < lbl_803E6220)
            {
                if (((DbEggState*)eggState)->flags119 & 0x10)
                {
                    ((DbEggState*)eggState)->mode = DBEGG_MODE_HOMING;
                }
                else
                {
                    ((DbEggState*)eggState)->mode = DBEGG_MODE_SETTLED;
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
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            }
            break;
        case DBEGG_MODE_SETTLED:
            if (((GameObject*)obj)->unkF8 == 0)
            {
                hitState->flags |= 1;
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            break;
        case DBEGG_MODE_DRIFTING:
            if (((DbEggState*)eggState)->flags119 & 4)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + (((DbeggPlacement*)data)->
                    targetPosX - ((GameObject*)obj)->anim.localPosX) / (fz = lbl_803E61E4);
                ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + (((DbeggPlacement*)data)->
                    targetPosY - ((GameObject*)obj)->anim.localPosY) / fz;
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + (((DbeggPlacement*)data)->
                    targetPosZ - ((GameObject*)obj)->anim.localPosZ) / fz;
                if (GameBit_Get(0x44d) != 0)
                {
                    ((DbEggState*)eggState)->mode = DBEGG_MODE_CURVE_INIT;
                }
            }
            hitState->flags |= 0x400;
            fz = lbl_803E61C8;
            flockVel[0] = lbl_803E61C8;
            flockVel[1] = fz;
            flockVel[2] = fz;
            fn_801FE774(obj, flockVel);
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + flockVel[0];
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + flockVel[1];
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + flockVel[2];
            if (fn_801FE560(obj, &h, ((GameObject*)obj)->anim.velocityX * timeDelta,
                            ((GameObject*)obj)->anim.velocityZ * timeDelta, 1) != 0)
            {
                ((GameObject*)obj)->anim.velocityX = lbl_803E6234 * ((GameObject*)obj)->anim.velocityX;
                ((GameObject*)obj)->anim.velocityZ = lbl_803E6234 * ((GameObject*)obj)->anim.velocityZ;
                fn_801FE560(obj, &h, ((GameObject*)obj)->anim.velocityX * timeDelta,
                            ((GameObject*)obj)->anim.velocityZ * timeDelta, 1);
            }
            h = h + ((DbEggState*)eggState)->waterOffset;
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
                int nb;
                nb = ((h < lbl_803E6200) >= 0) ? (h < lbl_803E6200) : -(h < lbl_803E6200);
                if (nb != 0)
                {
                    ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                        ((GameObject*)obj)->anim.localPosX,
                        ((GameObject*)obj)->anim.localPosY - ((DbEggState*)eggState)->waterOffset,
                        ((GameObject*)obj)->anim.localPosZ, ((GameObject*)obj)->anim.rotX, randomGetRange(1, 10), 1);
                }
            }
            if (GameBit_Get(0x426) != 0)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                ((DbEggState*)eggState)->waterOffset = ((DbEggState*)eggState)->waterOffset - lbl_803E623C * timeDelta;
                if (((DbEggState*)eggState)->waterOffset < lbl_803E61EC)
                {
                    GameBit_Set(0x428, GameBit_Get(0x428) + 1);
                    ((DbEggState*)eggState)->mode = DBEGG_MODE_SINKING;
                    fz = lbl_803E61C8;
                    ((GameObject*)obj)->anim.velocityY = lbl_803E61C8;
                    ((GameObject*)obj)->anim.velocityX = fz;
                    ((GameObject*)obj)->anim.velocityZ = fz;
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
            }
            else if (((DbEggState*)eggState)->flags119 & 2)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            }
            break;
        case DBEGG_MODE_INERT:
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            break;
        case DBEGG_MODE_PICKUP_PROMPT:
            if (Vec_xzDistance(obj + 0x18, data + 8) > lbl_803E6240 && (((DbEggState*)eggState)->flags119 & 2) == 0)
            {
                playerObj = Obj_GetPlayerObject();
                b2 = *(int*)&((GameObject*)obj)->extra;
                d2 = *(int*)&((GameObject*)obj)->anim.placementData;
                ObjGroup_RemoveObject(obj, 0x24);
                ((DbEggState*)b2)->mode = DBEGG_MODE_RELEASED;
                GameBit_Set(0x3c4, 1);
                GameBit_Set(0x86d, 1);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                GameBit_Set(((DbeggPlacement*)d2)->triggerGameBit, 1);
                ((DbEggState*)b2)->msg11C = -1;
                ((DbEggState*)b2)->msg11E = 0;
                ((DbEggState*)b2)->msg120 = lbl_803E61CC;
                ObjMsg_SendToObject(playerObj, 0x7000a, obj, b2 + 0x11c);
                ((GameObject*)obj)->unkF8 = 0;
            }
            else if (getButtonsJustPressed(0) & PAD_BUTTON_A)
            {
                ((DbEggState*)eggState)->mode = DBEGG_MODE_FALLING;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            }
            else
            {
                hitState->flags &= ~1;
                ObjMsg_SendToObject(player, 0x100008, obj, 0x38000);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            }
            break;
        case DBEGG_MODE_HELD:
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            return;
        case DBEGG_MODE_SINKING:
            fn_801FE560(obj, &h, lbl_803E61C8, *(f32*)&lbl_803E61C8, 0);
            v = h;
            v = v >= lbl_803E61C8 ? v : -v;
            if (v < lbl_803E6220)
            {
                ((DbEggState*)eggState)->mode = DBEGG_MODE_RESPAWN_WAIT;
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
        case DBEGG_MODE_RESPAWN_WAIT:
            if (GameBit_Get(0x42a) != 0)
            {
                dbegg_setupFromDef(obj, (int*)eggState);
            }
            else if (randomGetRange(0, 10) == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x3be, NULL, 0, -1, NULL);
            }
            break;
        case DBEGG_MODE_CURVE_INIT:
            if ((*gRomCurveInterface)->initCurve(&((DbEggState*)eggState)->curve, (void*)obj, lbl_803E624C,
                                                 curvePair, 2) != 0)
            {
                ((DbEggState*)eggState)->mode = DBEGG_MODE_FALLING;
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                ((DbEggState*)eggState)->mode = DBEGG_MODE_CURVE_FOLLOW;
                n = ((DbEggState*)eggState)->flags119;
                if (n & 4)
                {
                    ((DbEggState*)eggState)->flags119 = n & ~4;
                }
            }
            break;
        case DBEGG_MODE_CURVE_FOLLOW:
            if (Curve_AdvanceAlongPath(&((DbEggState*)eggState)->curve, lbl_803E6250) != 0 ||
                ((DbEggState*)eggState)->curve.atSegmentEnd != 0)
            {
                if ((*gRomCurveInterface)->goNextPoint((RomCurveWalker*)(eggState + 4)) != 0)
                {
                    ((DbEggState*)eggState)->mode = DBEGG_MODE_FALLING;
                }
            }
            else
            {
                ((GameObject*)obj)->anim.velocityX = ((DbEggState*)eggState)->curve.posX - ((GameObject*)obj)->anim.
                    localPosX;
                ((GameObject*)obj)->anim.velocityY = ((DbEggState*)eggState)->curve.posY - ((GameObject*)obj)->anim.
                    localPosY;
                ((GameObject*)obj)->anim.velocityZ = ((DbEggState*)eggState)->curve.posZ - ((GameObject*)obj)->anim.
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
        case DBEGG_MODE_GATED_RESPAWN:
            if (GameBit_Get(((DbeggPlacement*)data)->activateGameBit) != 0)
            {
                ObjGroup_AddObject(obj, 0x24);
                ((DbEggState*)eggState)->mode = DBEGG_MODE_FALLING;
            }
            break;
        case DBEGG_MODE_HOMING:
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
            Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_baddie_eba_smallswipe1);
            fz = *(f32*)((int)d + 8);
            fz = fz >= lbl_803E61C8 ? fz : -fz;
            fx = *(f32*)((int)d + 0);
            fx = fx >= *(f32*)&lbl_803E61C8 ? fx : -fx;
            if (fx + fz < lbl_803E625C)
            {
                ObjHits_EnableObject(obj);
                ((DbEggState*)eggState)->mode = DBEGG_MODE_SETTLED;
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
        if (((DbEggState*)eggState)->flags119 & 8)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            ObjHits_DisableObject(obj);
            if (GameBit_Get(((DbeggPlacement*)data)->triggerGameBit) != 0)
            {
                ((DbEggState*)eggState)->flags119 &= ~9;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                ObjHits_EnableObject(obj);
            }
        }
        else if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
        {
            if (GameBit_Get(0x3c4) == 0)
            {
                if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E6264)
                {
                    if ((((DbEggState*)eggState)->flags119 & 1) == 0)
                    {
                        playerObj = Obj_GetPlayerObject();
                        b2 = *(int*)&((GameObject*)obj)->extra;
                        d2 = *(int*)&((GameObject*)obj)->anim.placementData;
                        ObjGroup_RemoveObject(obj, 0x24);
                        ((DbEggState*)b2)->mode = DBEGG_MODE_RELEASED;
                        GameBit_Set(0x3c4, 1);
                        GameBit_Set(0x86d, 1);
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                        GameBit_Set(((DbeggPlacement*)d2)->triggerGameBit, 1);
                        ((DbEggState*)b2)->msg11C = -1;
                        ((DbEggState*)b2)->msg11E = 0;
                        ((DbEggState*)b2)->msg120 = lbl_803E61CC;
                        ObjMsg_SendToObject(playerObj, 0x7000a, obj, b2 + 0x11c);
                    }
                    else
                    {
                        v = ((GameObject*)obj)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
                        v = v >= lbl_803E61C8 ? v : -v;
                        if (v < lbl_803E6268)
                        {
                            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                            ((DbEggState*)eggState)->mode = DBEGG_MODE_PICKUP_PROMPT;
                            hitState->flags &= ~1;
                        }
                    }
                }
            }
        }
    }
#undef hitState
}

char sAnimGreaterMessage[11] = " GREATER \n\000";
