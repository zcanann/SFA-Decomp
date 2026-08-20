#include "dlls/object_descriptor.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "string.h"
#include "sys/objects.h"
#include "main/dll/rom_curve_def.h"
#include "game/objects/object.h"
#include "main/audio/sfx.h"
#include "main/dll/baddie_state.h"
#include "main/resource.h"
#include "main/dll/path_control_interface.h"
#include "main/vecmath.h"
#include "main/lightmap_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/dll/dll_000F_unk.h"
#include "main/audio/sfx_play_api.h"

u8 lbl_803DD450;
u8 lbl_803DD44F;
u8 lbl_803DD44E;
s16 gPlayerMoveTargetYaw;
f32 gPlayerMoveOverridePosX;
f32 gPlayerMoveOverridePosZ;
u8 gPlayerMoveAdvanced;
u32 gPlayerMoveFastMoveId;
u32 gPlayerMoveSlowMoveId;
u8 gPlayerMoveVelHandled;
u32 playerOverride;

#define PLAYER_MOVE_ZERO              0.0f
#define PLAYER_MOVE_DAMPING           0.9f
#define PLAYER_MOVE_INPUT_MAX         65.0f
#define PLAYER_MOVE_INPUT_MIN         -65.0f
#define PLAYER_MOVE_NEAR_DISTANCE     15.0f
#define PLAYER_MOVE_DISTANCE_SCALE    3.0f
#define PLAYER_MOVE_VELOCITY_DAMPING  0.97f
#define PLAYER_MOVE_DEG_TO_ANGLE      182.04f
#define PLAYER_MOVE_INPUT_THRESHOLD   0.05f
#define PLAYER_MOVE_QUARTER_TURN      16384.0f
#define PLAYER_MOVE_PI                3.1415927f
#define PLAYER_MOVE_HALF_CIRCLE       32768.0f
#define PLAYER_MOVE_CONTROL_MIN       0.02f
#define PLAYER_MOVE_ANIM_SPEED_MIN    0.04f
#define PLAYER_MOVE_OVERRIDE_MIN      0.1f
#define PLAYER_MOVE_DEGREES_PER_RAD   182.0f
#define PLAYER_MOVE_TIMER_LIMIT       10.0f
#define PLAYER_MOVE_ROTATION_SCALE    0.125f
#define PLAYER_MOVE_COUNTER_MAX       10000.0f

void player_moveTowardPoint(GameObject* a, int* ctx, f32 px, f32 pz, f32 lo, f32 hi, f32 spd)
{
    f32 dx;
    f32 dz;
    f32 mag;
    dx = a->anim.localPosX - px;
    dz = a->anim.localPosZ - pz;
    mag = sqrtf(dx * dx + dz * dz);
    ((BaddieState*)ctx)->moveTargetDistance = mag;
    if (PLAYER_MOVE_ZERO != mag)
    {
        dx = dx / mag;
        dz = dz / mag;
    }
    if (((BaddieState*)ctx)->moveTargetDistance > lo + hi)
    {
        ((BaddieState*)ctx)->moveInputX = dx * spd;
        ((BaddieState*)ctx)->moveInputZ = -dz * spd;
    }
    else
    {
        ((BaddieState*)ctx)->animSpeedC *= PLAYER_MOVE_DAMPING;
        ((BaddieState*)ctx)->moveInputZ = ((BaddieState*)ctx)->moveInputX = PLAYER_MOVE_ZERO;
    }
    if (((BaddieState*)ctx)->moveInputX > PLAYER_MOVE_INPUT_MAX)
    {
        ((BaddieState*)ctx)->moveInputX = PLAYER_MOVE_INPUT_MAX;
    }
    if (((BaddieState*)ctx)->moveInputX < PLAYER_MOVE_INPUT_MIN)
    {
        ((BaddieState*)ctx)->moveInputX = PLAYER_MOVE_INPUT_MIN;
    }
    if (((BaddieState*)ctx)->moveInputZ > PLAYER_MOVE_INPUT_MAX)
    {
        ((BaddieState*)ctx)->moveInputZ = PLAYER_MOVE_INPUT_MAX;
    }
    if (((BaddieState*)ctx)->moveInputZ < PLAYER_MOVE_INPUT_MIN)
    {
        ((BaddieState*)ctx)->moveInputZ = PLAYER_MOVE_INPUT_MIN;
    }
}

void player_followCurve(GameObject* obj, int* state, f32 cx, f32 cz, f32 t, int unused)
{
    f32 dx, dz, dist, max;

    *(u32*)state &= ~0x100000;
    dx = obj->anim.localPosX - cx;
    dz = obj->anim.localPosZ - cz;
    dist = sqrtf(dx * dx + dz * dz);
    ((BaddieState*)state)->moveTargetDistance = dist;
    max = PLAYER_MOVE_INPUT_MAX;
    if (((BaddieState*)state)->moveTargetDistance < PLAYER_MOVE_NEAR_DISTANCE)
    {
        max = PLAYER_MOVE_DISTANCE_SCALE * ((BaddieState*)state)->moveTargetDistance;
        ((BaddieState*)state)->animSpeedC *= PLAYER_MOVE_DAMPING;
    }
    if (dist > max)
    {
        f32 q = dist / max;
        dx = dx / q;
        dz = dz / q;
    }
    ((BaddieState*)state)->moveInputX = dx;
    ((BaddieState*)state)->moveInputZ = -dz;
    ((BaddieState*)state)->moveInputX = ((BaddieState*)state)->moveInputX * t;
    ((BaddieState*)state)->moveInputZ = ((BaddieState*)state)->moveInputZ * t;
    if (((BaddieState*)state)->moveInputX > PLAYER_MOVE_INPUT_MAX)
    {
        ((BaddieState*)state)->moveInputX = PLAYER_MOVE_INPUT_MAX;
    }
    if (((BaddieState*)state)->moveInputX < PLAYER_MOVE_INPUT_MIN)
    {
        ((BaddieState*)state)->moveInputX = PLAYER_MOVE_INPUT_MIN;
    }
    if (((BaddieState*)state)->moveInputZ > PLAYER_MOVE_INPUT_MAX)
    {
        ((BaddieState*)state)->moveInputZ = PLAYER_MOVE_INPUT_MAX;
    }
    if (((BaddieState*)state)->moveInputZ < PLAYER_MOVE_INPUT_MIN)
    {
        ((BaddieState*)state)->moveInputZ = PLAYER_MOVE_INPUT_MIN;
    }
}

const f32 gPlayerMoveOne[1] = {1.0f};

void player_applyVelocityStep(GameObject* obj, int* ctx, f32 t)
{
    int flags;
    int b;
    MatrixTransform desc;
    f32 mtx[16];
    f32 outY;
    f32 outX;
    f32 outZ;
    flags = ctx[0];
    if ((flags & 0x2000000) != 0)
    {
        return;
    }
    if ((flags & 0x200000) == 0)
    {
        obj->anim.velocityY *= PLAYER_MOVE_VELOCITY_DAMPING;
        obj->anim.velocityY = -(((BaddieState*)ctx)->gravity * t) + obj->anim.velocityY;
    }
    b = ((BaddieState*)ctx)->movementFlags;
    if ((b & 1) == 0 || (b & 4) != 0)
    {
        desc.rotX = obj->anim.rotX;
        desc.rotY = obj->anim.rotY;
        desc.rotZ = 0;
        desc.scale = gPlayerMoveOne[0];
        desc.x = PLAYER_MOVE_ZERO;
        desc.y = PLAYER_MOVE_ZERO;
        desc.z = PLAYER_MOVE_ZERO;
        setMatrixFromObjectPos(mtx, &desc);
        if ((ctx[0] & 0x10000) != 0)
        {
            Matrix_TransformPoint(mtx, ((BaddieState*)ctx)->animSpeedB, ((BaddieState*)ctx)->animSpeedY,
                                  -((BaddieState*)ctx)->animSpeedA, &outX, &obj->anim.velocityY, &outZ);
        }
        else
        {
            Matrix_TransformPoint(mtx, ((BaddieState*)ctx)->animSpeedB, PLAYER_MOVE_ZERO, -((BaddieState*)ctx)->animSpeedA,
                                  &outX, &outY, &outZ);
        }
        obj->anim.velocityX = outX;
        obj->anim.velocityZ = outZ;
    }
    objMove(obj, obj->anim.velocityX * t, obj->anim.velocityY * t,
            obj->anim.velocityZ * t);
}

void player_steerFromInput(GameObject* obj, int* ctx)
{
    int diff;
    f32 mx;
    f32 mz;
    *(f32*)&((BaddieState*)ctx)->trackedObj = ((BaddieState*)ctx)->inputMagnitude;
    mx = ((BaddieState*)ctx)->moveInputX * ((BaddieState*)ctx)->moveInputX;
    mz = ((BaddieState*)ctx)->moveInputZ * ((BaddieState*)ctx)->moveInputZ;
    ((BaddieState*)ctx)->inputMagnitude = sqrtf(mx + mz);
    if (((BaddieState*)ctx)->inputMagnitude > PLAYER_MOVE_INPUT_MAX)
    {
        ((BaddieState*)ctx)->inputMagnitude = PLAYER_MOVE_INPUT_MAX;
    }
    ((BaddieState*)ctx)->inputMagnitude = ((BaddieState*)ctx)->inputMagnitude / PLAYER_MOVE_INPUT_MAX;
    gPlayerMoveTargetYaw = getAngle(((BaddieState*)ctx)->moveInputX, -((BaddieState*)ctx)->moveInputZ);
    gPlayerMoveTargetYaw -= ((BaddieState*)ctx)->cameraYaw;
    diff = gPlayerMoveTargetYaw;
    diff -= (u16)obj->anim.rotX;
    if (diff > 0x8000)
    {
        diff -= 0xffff;
    }
    if (diff < -0x8000)
    {
        diff += 0xffff;
    }
    ((BaddieState*)ctx)->turnRate = ((f32)diff / PLAYER_MOVE_DEG_TO_ANGLE);
    if (diff < 0)
    {
        ((BaddieState*)ctx)->turnRateAbs = -((BaddieState*)ctx)->turnRate;
    }
    else
    {
        ((BaddieState*)ctx)->turnRateAbs = ((BaddieState*)ctx)->turnRate;
    }
    diff = diff + 0x10000u;
    if (((BaddieState*)ctx)->inputMagnitude < PLAYER_MOVE_INPUT_THRESHOLD)
    {
        ((BaddieState*)ctx)->inputSector = 0;
    }
    else
    {
        diff -= 0x6000;
        if (diff < 0)
        {
            diff += 0xffff;
        }
        if (diff > 0xffff)
        {
            diff -= 0xffff;
        }
        ((BaddieState*)ctx)->inputSector = (u8)(4 - diff / 0x4000);
    }
}

void player_updateParticles(GameObject* obj, int unused, int effectId, int count, int mode)
{
    while (count != 0 && obj != NULL)
    {
        if (mode == 0)
        {
            (*gPartfxInterface)->spawnObject(obj, effectId, NULL, 2, -1, NULL);
        }
        else if (mode == 1)
        {
            (*gPartfxInterface)->spawnObject(obj, effectId, NULL, 2, -1, NULL);
        }
        else if (mode == 2)
        {
            (*gPartfxInterface)->spawnObject(obj, effectId, NULL, 4, -1, NULL);
        }
        count--;
    }
}

void player_doProjGfx(GameObject* obj, int unusedA, int resIdBase, int count, int unusedB, int mode)
{
    /* res: acquired projectile-gfx resource; its vtable slot [+4] is the
     * per-instance spawn entry, dispatched `count` times with a mode-selected
     * flag (1/2/4). */
    void* res = Resource_Acquire((u16)(resIdBase + 0x58), 1);
    while (count != 0)
    {
        if (mode == 0)
        {
            (*(void (*)(GameObject*, int, int, int, int, int))(*(int*)(*(int*)res + 4)))(obj, 0, 0, 1, -1, 0);
        }
        else if (mode == 1)
        {
            (*(void (*)(GameObject*, int, int, int, int, int))(*(int*)(*(int*)res + 4)))(obj, 0, 0, 2, -1, 0);
        }
        else if (mode == 2)
        {
            (*(void (*)(GameObject*, int, int, int, int, int))(*(int*)(*(int*)res + 4)))(obj, 0, 0, 4, -1, 0);
        }
        count--;
    }
    Resource_Release(res);
}

void player_updateSecondaryBlend(GameObject* obj, int* ctx, int moveA, int moveB)
{
    f32 mag;
    f32 tmp;
    f32 q1, q2;
    f64 ratio;
    int idx;
    if ((s8)gPlayerMoveVelHandled != 0)
    {
        f32 speedA = ((BaddieState*)ctx)->animSpeedA;
        if (speedA > PLAYER_MOVE_ZERO && obj->anim.currentMove != (int)gPlayerMoveFastMoveId)
        {
            ObjAnim_SetCurrentMove(obj, gPlayerMoveFastMoveId, obj->anim.currentMoveProgress, 0);
            ((BaddieState*)ctx)->moveDone = 0;
        }
        else if (speedA < PLAYER_MOVE_ZERO && obj->anim.currentMove != (int)gPlayerMoveSlowMoveId)
        {
            ObjAnim_SetCurrentMove(obj, gPlayerMoveSlowMoveId, obj->anim.currentMoveProgress, 0);
            ((BaddieState*)ctx)->moveDone = 0;
        }
        q1 = ((BaddieState*)ctx)->animSpeedA * ((BaddieState*)ctx)->animSpeedA;
        q2 = ((BaddieState*)ctx)->animSpeedB * ((BaddieState*)ctx)->animSpeedB;
        mag = sqrtf(q1 + q2);
        if (ObjAnim_SampleRootCurvePhase(&obj->anim, mag, &tmp) != 0)
        {
            ((BaddieState*)ctx)->moveSpeed = tmp;
        }
        tmp = (PLAYER_MOVE_ZERO != mag) ? ((BaddieState*)ctx)->animSpeedB / mag : PLAYER_MOVE_ZERO;
        ratio = tmp;
        idx = (int)(PLAYER_MOVE_QUARTER_TURN * (f32)ratio);
        if (idx < 0)
        {
            idx = -idx;
        }
        if ((f32)idx > PLAYER_MOVE_QUARTER_TURN)
        {
            idx = 0x4000;
        }
        if (((BaddieState*)ctx)->animSpeedB > PLAYER_MOVE_ZERO)
        {
            Object_ObjAnimSetSecondaryBlendMove(&obj->anim, moveB, idx);
        }
        else
        {
            Object_ObjAnimSetSecondaryBlendMove(&obj->anim, moveA, idx);
        }
    }
}

void player_setAnimIds(int unused1, int unused2, u32 a, u32 b)
{
    gPlayerMoveFastMoveId = a;
    gPlayerMoveSlowMoveId = b;
}

void player_clearXZvel(GameObject* obj, int* state)
{
    f32 z = PLAYER_MOVE_ZERO;
    obj->anim.velocityX = z;
    obj->anim.velocityZ = z;
    ((BaddieState*)state)->animSpeedC = z;
    ((BaddieState*)state)->animSpeedA = z;
    ((BaddieState*)state)->animSpeedB = z;
}

void dll_0F_func13(GameObject* obj, int* state, int angle, f32 t, f32 scale)
{
    f32 ang, vx, vz, q, w, dist, s, c;

    ((BaddieState*)state)->movementFlags |= 1;
    if ((s8)gPlayerMoveVelHandled == 0)
    {
        ang = (PLAYER_MOVE_PI * angle) / PLAYER_MOVE_HALF_CIRCLE;
        vx = scale * (((BaddieState*)state)->inputMagnitude * -mathSinf(ang));
        vz = scale * (((BaddieState*)state)->inputMagnitude * -mathCosf(ang));
        if (((BaddieState*)state)->inputMagnitude < PLAYER_MOVE_CONTROL_MIN)
        {
            vx = PLAYER_MOVE_ZERO;
            vz = vx;
        }
        obj->anim.velocityX =
            obj->anim.velocityX +
            (t * (vx - obj->anim.velocityX)) / ((BaddieState*)state)->velSmoothTime;
        obj->anim.velocityZ =
            obj->anim.velocityZ +
            (t * (vz - obj->anim.velocityZ)) / ((BaddieState*)state)->velSmoothTime;
    }
    else
    {
        ((BaddieState*)state)->movementFlags &= ~1;
    }
    q = obj->anim.velocityX * obj->anim.velocityX;
    w = obj->anim.velocityZ * obj->anim.velocityZ;
    dist = sqrtf(q + w);
    ((BaddieState*)state)->animSpeedC = dist;
    if (((BaddieState*)state)->animSpeedC < PLAYER_MOVE_ANIM_SPEED_MIN)
    {
        f32 z = PLAYER_MOVE_ZERO;
        ((BaddieState*)state)->animSpeedC = z;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
    }
    s = mathSinf((PLAYER_MOVE_PI * (f32)*(s16*)obj) / PLAYER_MOVE_HALF_CIRCLE);
    c = mathCosf((PLAYER_MOVE_PI * (f32)*(s16*)obj) / PLAYER_MOVE_HALF_CIRCLE);
    ((BaddieState*)state)->animSpeedB = obj->anim.velocityX * c - obj->anim.velocityZ * s;
    ((BaddieState*)state)->animSpeedA =
        -obj->anim.velocityZ * c - obj->anim.velocityX * s;
}

void dll_0F_func19_nop(void)
{
}

void player_updateCurve(GameObject* obj, int* state, f32 t)
{
    int idx = ((BaddieState*)state)->curveId;
    if (idx == -1)
    {
        ((BaddieState*)state)->moveTargetDistance = PLAYER_MOVE_ZERO;
    }
    else
    {
        RomCurveDef* curve = (RomCurveDef*)((int*)(*gRomCurveInterface)->getById(idx));
        if (curve == NULL)
        {
            ((BaddieState*)state)->moveTargetDistance = PLAYER_MOVE_ZERO;
        }
        else
        {
            player_followCurve(obj, state, curve->x, curve->z, t, 1);
        }
    }
}


void player_findCurve(GameObject* obj, int* state, int curveId)
{
    ((BaddieState*)state)->curveId = (*gRomCurveInterface)->find(
        obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
        &curveId, 1, ((BaddieState*)state)->curveSearchFilter);
}

void player_playSoundFn10(GameObject* obj, int* state, int bit, int idx, int* sfxTable)
{
    register int flags;
    register int mask;
    mask = 1 << bit;
    flags = ((BaddieState*)state)->eventFlags;
    if ((flags & mask) != 0)
    {
        ((BaddieState*)state)->eventFlags = flags & ~mask;
        Sfx_PlayFromObject(obj, (u16)sfxTable[idx]);
    }
}

void player_playSoundFn0F(GameObject* obj, int* state, int bit, int idx, int* sfxTable)
{
    register int flags;
    register int mask;
    mask = 1 << bit;
    flags = ((BaddieState*)state)->eventFlags;
    if ((flags & mask) != 0)
    {
        ((BaddieState*)state)->eventFlags = flags & ~mask;
        Sfx_PlayFromObject(obj, (u16)sfxTable[idx]);
    }
}

void player_rotateTowardEnemy(GameObject* obj, int* ctx, int spd)
{
    GameObject* enemy;
    f32 dx;
    f32 dz;
    int diff;
    enemy = (GameObject*)((BaddieState*)ctx)->targetObj;
    if (enemy != 0)
    {
        if (enemy->anim.parent == obj->anim.parent)
        {
            dx = enemy->anim.localPosX - obj->anim.localPosX;
            dz = enemy->anim.localPosZ - obj->anim.localPosZ;
        }
        else
        {
            dx = obj->anim.worldPosX - enemy->anim.worldPosX;
            dz = obj->anim.worldPosZ - enemy->anim.worldPosZ;
        }
        diff = (u16)getAngle(-dx, -dz) - (u16)obj->anim.rotX;
        if (diff > 0x8000)
        {
            diff -= 0xffff;
        }
        if (diff < -0x8000)
        {
            diff += 0xffff;
        }
        obj->anim.rotX =
            (s16)(obj->anim.rotX + (int)((f32)diff * timeDelta / (PLAYER_MOVE_DISTANCE_SCALE * spd)));
    }
}

void player_render2(GameObject* obj, int* state, f32 f1, f32 f2)
{
    f32 cur = ((BaddieState*)state)->nudgeYawProgress;
    f32 new_ = f2 * f1 + cur;
    if (new_ > gPlayerMoveOne[0])
    {
        new_ = gPlayerMoveOne[0];
    }
    {
        f32 delta = new_ - cur;
        if (delta > PLAYER_MOVE_ZERO)
        {
            *(s16*)obj += (s16)(((BaddieState*)state)->nudgeYaw * delta);
            ((BaddieState*)state)->nudgeYawProgress = new_;
        }
    }
}

void player_modelMtxFn(f32* mtx, int* state, f32 f1, f32 f2)
{
    f32 cur = ((BaddieState*)state)->nudgePosProgress;
    f32 new_ = f2 * f1 + cur;
    if (new_ > gPlayerMoveOne[0])
    {
        new_ = gPlayerMoveOne[0];
    }
    {
        f32 delta = new_ - cur;
        if (delta > PLAYER_MOVE_ZERO)
        {
            mtx[3] = ((BaddieState*)state)->nudgePosX * delta + mtx[3];
            mtx[4] = ((BaddieState*)state)->nudgePosY * delta + mtx[4];
            mtx[5] = ((BaddieState*)state)->nudgePosZ * delta + mtx[5];
            ((BaddieState*)state)->nudgePosProgress = new_;
        }
    }
}

void dll_0F_func0B(GameObject* obj, int* state, f32 f1, f32 f2, f32 f3)
{
    if (((BaddieState*)state)->inputMagnitude > PLAYER_MOVE_OVERRIDE_MIN)
    {
        f32 q = (f2 * f1) / f3;
        obj->anim.rotX = (f32)*(s16*)obj + PLAYER_MOVE_DEGREES_PER_RAD * q;
    }
}

void player_advanceMove(short* moveState, u32* obj, f32 dt, int flags)
{
    PlayerMoveBuf buf;
    s8* ptr;
    int i;
    f32 stopVal;

    buf.flag = 0;
    ((BaddieState*)obj)->moveDone =
        ObjAnim_AdvanceCurrentMove(moveState, ((BaddieState*)obj)->moveSpeed, dt, (ObjAnimEventList*)&buf);

    ((BaddieState*)obj)->eventFlags = 0;
    i = 0;
    ptr = (s8*)&buf;
    for (; i < buf.count; i++)
    {
        ((BaddieState*)obj)->eventFlags |= 1 << ptr[0x13];
        ptr++;
    }

    *obj &= ~0x10000;

    if (buf.flag != 0)
    {
        if ((flags & 0x10) != 0)
        {
            if ((flags & 1) != 0)
            {
                ((BaddieState*)obj)->rootMotionDelta = -buf.c;
            }
            if ((flags & 2) != 0)
            {
                ((BaddieState*)obj)->rootMotionDelta = buf.a;
            }
            if ((flags & 4) != 0)
            {
                ((BaddieState*)obj)->rootMotionDelta = buf.b;
            }
            if ((flags & 8) != 0)
            {
                *moveState += buf.angleDelta;
            }
        }
        else
        {
            if ((flags & 1) != 0)
            {
                ((BaddieState*)obj)->animSpeedA = -buf.c / dt;
            }
            if ((flags & 2) != 0)
            {
                ((BaddieState*)obj)->animSpeedB = buf.a / dt;
            }
            if ((flags & 8) != 0)
            {
                *moveState += buf.angleDelta;
            }
            if ((flags & 4) != 0)
            {
                ((BaddieState*)obj)->animSpeedY = buf.b / dt;
                *obj |= 0x10000;
            }
        }
    }
    else
    {
        stopVal = PLAYER_MOVE_ZERO;
        ((BaddieState*)obj)->animSpeedA = stopVal;
        ((BaddieState*)obj)->animSpeedB = stopVal;
    }

    gPlayerMoveAdvanced = 1;
}

void player_runSubstateMachine(GameObject* gameObj, BaddieState* state, f32 dt, PlayerSubstateFn* stateFns)
{
    int iterations;
    int startState;
    int done;
    int result;
    int stateChanged;

    stateChanged = 0;
    iterations = 0;
    if (state->substate != state->prevSubstate)
    {
        state->moveJustStartedB = 1;
        state->stateTimer = 0;
    }
    do
    {
        done = 0;
        startState = state->substate;
        result = stateFns[startState](gameObj, state, dt);
        if (result > 0)
        {
            state->prevSubstate = state->substate;
            state->substate = result - 1;
            state->moveJustStartedB = 1;
            state->stateTimer = 0;
        }
        else if (result < 0)
        {
            result = -result;
            if (result != startState)
            {
                s16 previousState = startState;
                startState = previousState;
                state->prevSubstate = startState;
                state->moveJustStartedB = 1;
                state->stateTimer = 0;
            }
            else
            {
                state->moveJustStartedB = 0;
            }
            state->substate = result;
            done = 1;
            stateChanged = 1;
        }
        else
        {
            done = 1;
        }
        iterations++;
        if (iterations > 0xff)
        {
            done = 1;
        }
    } while (done == 0);
    state->prevSubstate = state->substate;
    if (stateChanged == 0)
    {
        state->moveJustStartedB = 0;
        if (state->controlTimer > PLAYER_MOVE_TIMER_LIMIT)
        {
            state->moveJustStartedB = 0;
        }
    }
}

void playerRunStateMachine(GameObject* obj, BaddieState* state, f32 dt, PlayerStateFn* stateFns)
{
    int iterations;
    int currentState;
    int done;
    int result;
    PlayerStateExitFn exitFn;
    int changed;

    changed = 0;
    iterations = 0;
    lbl_803DD450 = 0;
    gPlayerMoveAdvanced = 0;

    if (state->controlMode != state->prevControlMode)
    {
        state->moveJustStartedA = 1;
        state->controlTimer = 0;
    }

    do
    {
        done = 0;
        currentState = state->controlMode;
        result = stateFns[currentState](obj, state, dt);
        if (result > 0)
        {
            state->prevControlMode = state->controlMode;
            state->controlMode = (s16)(result - 1);
            exitFn = state->stateExitFn;
            if (exitFn != NULL)
            {
                exitFn(obj, state);
                state->stateExitFn = NULL;
            }
            state->stateExitFn = state->nextStateExitFn;
            state->moveJustStartedA = 1;
            state->controlTimer = 0;
            state->stateTag = 0;
            state->movementFlags = 0;
            state->moveEventFlags = 0;
            state->stateId = 0;
            if (obj->anim.hitReactState != NULL)
            {
                ((ObjHitsPriorityState*)obj->anim.hitReactState)->suppressOutgoingHits = 0;
            }
        }
        else if (result < 0)
        {
            result = -result;
            state->controlMode = result;
            if (result != currentState)
            {
                currentState = (s16)currentState;
                state->prevControlMode = currentState;
                exitFn = state->stateExitFn;
                if (exitFn != NULL)
                {
                    exitFn(obj, state);
                    state->stateExitFn = NULL;
                }
                state->stateExitFn = state->nextStateExitFn;
                state->moveJustStartedA = 1;
                state->controlTimer = 0;
                state->stateTag = 0;
                state->movementFlags = 0;
                state->moveEventFlags = 0;
                state->stateId = 0;
                if (obj->anim.hitReactState != NULL)
                {
                    ((ObjHitsPriorityState*)obj->anim.hitReactState)->suppressOutgoingHits = 0;
                }
            }
            done = 1;
            changed = 1;
        }
        else
        {
            done = 1;
        }

        iterations++;
        if (iterations > 0xff)
        {
            done = 1;
        }
    } while (done == 0);

    if (changed == 0)
    {
        state->moveJustStartedA = 0;
    }
    state->prevControlMode = state->controlMode;

    if ((s8)gPlayerMoveAdvanced == 0 && ((s32)state->movementFlags & 1) == 0)
    {
        ObjAnimEventList animEvents;
        int i;

        animEvents.triggerCount = 0;
        state->moveDone = ObjAnim_AdvanceCurrentMove(obj, state->moveSpeed, dt, &animEvents);
        state->eventFlags = 0;
        for (i = 0; i < animEvents.triggerCount; i++)
        {
            state->eventFlags |= 1 << animEvents.triggeredIds[i];
        }
        state->flags0 &= ~0x10000;
    }

    if ((s32)(state->flags0 & 0x4000) == 0)
    {
        f32 t;

        t = (f32)(int)obj->anim.rotY * dt;
        t *= PLAYER_MOVE_ROTATION_SCALE;
        obj->anim.rotY -= (s16)t;
        t = (f32)(int)obj->anim.rotZ * dt;
        t *= PLAYER_MOVE_ROTATION_SCALE;
        obj->anim.rotZ -= (s16)t;
    }
}

void player_setState(void* ctx, void* p, int new_state)
{
    ObjHitsPriorityState* q;
    if (((BaddieState*)p)->controlMode != new_state)
    {
        ((BaddieState*)p)->prevControlMode = ((BaddieState*)p)->controlMode;
        ((BaddieState*)p)->controlMode = new_state;
        {
            void (*fn)(void) = *(void (**)(void))&((BaddieState*)p)->stateExitFn;
            if (fn != 0)
            {
                fn();
                *(void**)&((BaddieState*)p)->stateExitFn = 0;
            }
        }
        *(void**)&((BaddieState*)p)->stateExitFn = (void*)((BaddieState*)p)->nextStateExitFn;
    }
    ((BaddieState*)p)->controlTimer = 0;
    ((BaddieState*)p)->moveJustStartedA = 1;
    ((BaddieState*)p)->stateTag = 0;
    ((BaddieState*)p)->movementFlags = 0;
    ((BaddieState*)p)->moveEventFlags = 0;
    ((BaddieState*)p)->stateId = 0;
    q = (ObjHitsPriorityState*)((GameObject*)ctx)->anim.hitReactState;
    if (q != 0)
        q->suppressOutgoingHits = 0;
}

void player_setOverride(u32 x)
{
    playerOverride = x;
}

void player_updateVel(char* p, char* obj, void* stateFns)
{
    float fcos, fsin;
    f32 vx;
    f32 vz;
    if (((s32)((BaddieState*)obj)->movementFlags & 1) != 0)
    {
        fcos = mathSinf(PLAYER_MOVE_PI * (float)(s32)((GameObject*)p)->anim.rotX / PLAYER_MOVE_HALF_CIRCLE);
        fsin = mathCosf(PLAYER_MOVE_PI * (float)(s32)((GameObject*)p)->anim.rotX / PLAYER_MOVE_HALF_CIRCLE);
        if (((s32)((BaddieState*)obj)->movementFlags & 8) != 0)
        {
            ((BaddieState*)obj)->animSpeedA =
                -((GameObject*)p)->anim.velocityZ * fsin - ((GameObject*)p)->anim.velocityX * fcos;
            ((BaddieState*)obj)->animSpeedC = ((BaddieState*)obj)->animSpeedA;
        }
        else
        {
            ((BaddieState*)obj)->animSpeedB =
                ((GameObject*)p)->anim.velocityX * fsin - ((GameObject*)p)->anim.velocityZ * fcos;
            ((BaddieState*)obj)->animSpeedA =
                -((GameObject*)p)->anim.velocityZ * fsin - ((GameObject*)p)->anim.velocityX * fcos;
            if ((((BaddieState*)obj)->movementFlags & 4) != 0)
            {
                vx = ((GameObject*)p)->anim.velocityX * ((GameObject*)p)->anim.velocityX;
                vz = ((GameObject*)p)->anim.velocityZ * ((GameObject*)p)->anim.velocityZ;
                ((BaddieState*)obj)->animSpeedC = sqrtf(vx + vz);
            }
        }
        ((BaddieState*)obj)->movementFlags = 0;
        *(u32*)obj |= 0x80000;
        gPlayerMoveVelHandled = 1;
        lbl_803DD44F = 0;
        lbl_803DD44E = 1;
        playerRunStateMachine((GameObject*)p, (BaddieState*)obj, timeDelta, (PlayerStateFn*)stateFns);
    }
}

void player_update(char* pos, char* state, float dt, float pathDt, void* stateFns, void* auxStateFns)
{
    MatrixTransform localTransform;
    f32 matrix[16];
    int keepPathControls;
    GameObject* attachment;
    f32* axes;
    int mapBlock;
    GameObject* overrideObj;
    f32 dx;
    f32 dz;
    f32 dist;
    f32 limit;
    f32 ldx;
    f32 ldz;
    void* pathObj;

    keepPathControls = 1;
    lbl_803DD44E = 0;

    attachment = ((BaddieState*)state)->targetObj;
    if (attachment != NULL)
    {
        dx = attachment->anim.localPosX - ((GameObject*)pos)->anim.localPosX;
        dz = attachment->anim.localPosZ - ((GameObject*)pos)->anim.localPosZ;
        ((BaddieState*)state)->targetDistance = sqrtf(dx * dx + dz * dz);
    }
    else
    {
        ((BaddieState*)state)->targetDistance = PLAYER_MOVE_ZERO;
    }

    pathObj = ((GameObject*)pos)->pendingParentObj;
    if ((*(int*)state & 0x8000) != 0 && pathObj == NULL)
    {
        player_runSubstateMachine((GameObject*)pos, (BaddieState*)state, dt, (PlayerSubstateFn*)auxStateFns);
        ((BaddieState*)state)->stateTimer = (s16)((f32)((BaddieState*)state)->stateTimer + dt);
        if ((f32)((BaddieState*)state)->stateTimer > PLAYER_MOVE_COUNTER_MAX)
        {
            ((BaddieState*)state)->stateTimer = 10000;
        }
    }

    *(u32*)state |= 0x8000;

    if (((BaddieState*)state)->orientationAxesOut != NULL)
    {
        localTransform.rotX = ((GameObject*)pos)->anim.rotX;
        localTransform.rotY = ((GameObject*)pos)->anim.rotY;
        localTransform.rotZ = ((GameObject*)pos)->anim.rotZ;
        localTransform.scale = gPlayerMoveOne[0];
        localTransform.x = PLAYER_MOVE_ZERO;
        localTransform.y = PLAYER_MOVE_ZERO;
        localTransform.z = PLAYER_MOVE_ZERO;
        setMatrixFromObjectPos(matrix, &localTransform);

        axes = ((BaddieState*)state)->orientationAxesOut;
        Matrix_TransformPoint(matrix, PLAYER_MOVE_ZERO, PLAYER_MOVE_ZERO, gPlayerMoveOne[0], &axes[0], &axes[1],
                              &axes[2]);
        axes = ((BaddieState*)state)->orientationAxesOut;
        Matrix_TransformPoint(matrix, PLAYER_MOVE_ZERO, gPlayerMoveOne[0], PLAYER_MOVE_ZERO, &axes[3], &axes[4],
                              &axes[5]);
        axes = ((BaddieState*)state)->orientationAxesOut;
        Matrix_TransformPoint(matrix, gPlayerMoveOne[0], PLAYER_MOVE_ZERO, PLAYER_MOVE_ZERO, &axes[6], &axes[7],
                              &axes[8]);
    }

    if ((*(int*)state & 0x1000000) == 0)
    {
        player_steerFromInput((GameObject*)pos, (int*)state);
    }

    *(u32*)state &= 0xffdfffff;
    ((BaddieState*)state)->stateTag = 0;
    gPlayerMoveVelHandled = 0;
    *(u32*)state &= 0xfff7ffff;
    ((BaddieState*)state)->movementFlags = 0;
    lbl_803DD44F = 0;

    playerRunStateMachine((GameObject*)pos, (BaddieState*)state, dt, (PlayerStateFn*)stateFns);

    ((BaddieState*)state)->controlTimer =
        (s16)((f32)((BaddieState*)state)->controlTimer + dt);
    if ((f32)((BaddieState*)state)->controlTimer > PLAYER_MOVE_COUNTER_MAX)
    {
        ((BaddieState*)state)->controlTimer = 10000;
    }

    gPlayerMoveOverridePosX = ((GameObject*)pos)->anim.localPosX;
    gPlayerMoveOverridePosZ = ((GameObject*)pos)->anim.localPosZ;
    mapBlock = objPosToMapBlockIdx(((GameObject*)pos)->anim.worldPosX, ((GameObject*)pos)->anim.worldPosY,
                                   ((GameObject*)pos)->anim.worldPosZ);
    if (mapBlock == -1 && ((GameObject*)pos)->anim.parent == NULL)
    {
        *(u32*)state |= 0x200000;
        keepPathControls = 0;
    }

    if ((*(int*)state & 0x1000000) == 0)
    {
        player_applyVelocityStep((GameObject*)pos, (int*)state, dt);
    }

    overrideObj = (GameObject*)playerOverride;
    if ((void*)overrideObj != NULL)
    {
        dx = overrideObj->anim.localPosX - gPlayerMoveOverridePosX;
        dz = overrideObj->anim.localPosZ - gPlayerMoveOverridePosZ;
        dist = sqrtf(dx * dx + dz * dz);
        if (dist < PLAYER_MOVE_TIMER_LIMIT)
        {
            ldx = ((GameObject*)pos)->anim.localPosX - gPlayerMoveOverridePosX;
            ldz = ((GameObject*)pos)->anim.localPosZ - gPlayerMoveOverridePosZ;
            limit = sqrtf(ldx * ldx + ldz * ldz);
            if (limit < PLAYER_MOVE_OVERRIDE_MIN)
            {
                limit = PLAYER_MOVE_OVERRIDE_MIN;
            }

            if (dist < gPlayerMoveOne[0])
            {
                ((GameObject*)pos)->anim.localPosX = overrideObj->anim.localPosX;
                ((GameObject*)pos)->anim.localPosZ = overrideObj->anim.localPosZ;
            }
            else
            {
                if (limit > dist)
                {
                    limit = dist;
                }
                dx = dx / dist;
                dz = dz / dist;
                ((GameObject*)pos)->anim.localPosX = dx * limit + gPlayerMoveOverridePosX;
                ((GameObject*)pos)->anim.localPosZ = dz * limit + gPlayerMoveOverridePosZ;
            }
        }
    }

    playerOverride = 0;

    if ((*(int*)state & 0x1000000) == 0 && (*(int*)state & 0x400000) == 0 && keepPathControls != 0)
    {
        (*gPathControlInterface)->update(pos, state + 0x4, dt);
        (*gPathControlInterface)->apply(pos, state + 0x4);
        (*gPathControlInterface)->advance(pos, state + 0x4, pathDt);

        if (((s32)((BaddieState*)state)->surfaceFlags & 0x10) != 0)
        {
            *(u32*)state |= 0x40000;
        }
        else
        {
            *(u32*)state &= 0xfffbffff;
        }

        if ((*(int*)state & 0x800000) != 0)
        {
            if (((s32)((BaddieState*)state)->surfaceFlags & 2) != 0 || ((BaddieState*)state)->groundContact != 0)
            {
                ((GameObject*)pos)->anim.velocityX =
                    (((GameObject*)pos)->anim.localPosX -
                     ((ObjHitsPriorityState*)((GameObject*)pos)->anim.hitReactState)->localPosX) /
                    dt;
                ((GameObject*)pos)->anim.velocityZ =
                    (((GameObject*)pos)->anim.localPosZ -
                     ((ObjHitsPriorityState*)((GameObject*)pos)->anim.hitReactState)->localPosZ) /
                    dt;
            }
            *(u32*)state &= 0xff7fffff;
        }
    }
}



void player_init(void* unused, void* obj, int a, int b)
{
    memset(obj, 0, sizeof(BaddieState));
    ((BaddieState*)obj)->unk26C = a;
    ((BaddieState*)obj)->unk26E = b;
    ((BaddieState*)obj)->moveJustStartedA = 1;
    ((BaddieState*)obj)->moveJustStartedB = 1;
    ((BaddieState*)obj)->velSmoothTime = PLAYER_MOVE_TIMER_LIMIT;
    ((BaddieState*)obj)->curveId = -1;
    ((BaddieState*)obj)->unk340 = -1;
    ((BaddieState*)obj)->unk358 = 0;
}

void player_release(void)
{
}

void player_initialise(void)
{
}
typedef struct PlayerDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback init;
    ObjectDescriptorCallback update;
    ObjectDescriptorCallback updateVel;
    ObjectDescriptorCallback setOverride;
    ObjectDescriptorCallback setState;
    ObjectDescriptorCallback followCurve;
    ObjectDescriptorCallback moveTowardPoint;
    ObjectDescriptorCallback advanceMove;
    ObjectDescriptorCallback slot0B;
    ObjectDescriptorCallback modelMtxFn;
    ObjectDescriptorCallback render2;
    ObjectDescriptorCallback rotateTowardEnemy;
    ObjectDescriptorCallback playSoundFn0F;
    ObjectDescriptorCallback playSoundFn10;
    ObjectDescriptorCallback findCurve;
    ObjectDescriptorCallback updateCurve;
    ObjectDescriptorCallback slot13;
    ObjectDescriptorCallback clearXZvel;
    ObjectDescriptorCallback setAnimIds;
    ObjectDescriptorCallback updateSecondaryBlend;
    ObjectDescriptorCallback doProjGfx;
    ObjectDescriptorCallback updateParticles;
    ObjectDescriptorCallback slot19;
} PlayerDllInterface;

PlayerDllInterface player_funcs = {
    0,
    0,
    0,
    0x00190000,
    (ObjectDescriptorCallback)player_initialise,
    (ObjectDescriptorCallback)player_release,
    0,
    (ObjectDescriptorCallback)player_init,
    (ObjectDescriptorCallback)player_update,
    (ObjectDescriptorCallback)player_updateVel,
    (ObjectDescriptorCallback)player_setOverride,
    (ObjectDescriptorCallback)player_setState,
    (ObjectDescriptorCallback)player_followCurve,
    (ObjectDescriptorCallback)player_moveTowardPoint,
    (ObjectDescriptorCallback)player_advanceMove,
    (ObjectDescriptorCallback)dll_0F_func0B,
    (ObjectDescriptorCallback)player_modelMtxFn,
    (ObjectDescriptorCallback)player_render2,
    (ObjectDescriptorCallback)player_rotateTowardEnemy,
    (ObjectDescriptorCallback)player_playSoundFn0F,
    (ObjectDescriptorCallback)player_playSoundFn10,
    (ObjectDescriptorCallback)player_findCurve,
    (ObjectDescriptorCallback)player_updateCurve,
    (ObjectDescriptorCallback)dll_0F_func13,
    (ObjectDescriptorCallback)player_clearXZvel,
    (ObjectDescriptorCallback)player_setAnimIds,
    (ObjectDescriptorCallback)player_updateSecondaryBlend,
    (ObjectDescriptorCallback)player_doProjGfx,
    (ObjectDescriptorCallback)player_updateParticles,
    (ObjectDescriptorCallback)dll_0F_func19_nop,
};
