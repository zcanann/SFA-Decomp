/*
 * dll_000F: the shared "player_*" movement controller used by the
 * follow / escort objects (BaddieState-driven). It runs a small per-object
 * state machine (playerRunStateMachine / fn_800D915C step a table of state
 * functions + their substates), does curve following (player_followCurve /
 * player_updateCurve through gRomCurveInterface), input-magnitude yaw
 * steering (fn_800D8414), gravity + matrix-relative velocity integration
 * (player_applyVelocityStep / objMove), per-move animation-event sound
 * triggers (player_playSoundFn0F/10) and particle/projectile gfx spawns
 * (player_updateParticles / player_doProjGfx). Most tuning values live in
 * cross-TU .sdata2 floats (lbl_803Exxxx); the lbl_803DD4xx globals are
 * per-frame scratch carrying yaw/position between the update sub-passes.
 */
#include "main/dll/rom_curve_interface.h"
#include "main/dll/objfsa_romcurve.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/resource.h"
#include "main/dll/path_control_interface.h"
#include "string.h"
#include "main/vecmath.h"
#include "main/sfa_shared_decls.h"
extern int getAngle(float y, float x);
extern f32 sqrtf(f32 x);
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern void player_followCurve(int* obj, int* state, f32 a, f32 b, f32 t, int p5);
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern void objMove(int* obj, f32 vx, f32 vy, f32 vz);
extern void fn_800D915C(int pos, int* obj, f32 fval, void* fnTable);

extern u32 gPlayerMoveSlowMoveId;
extern u32 gPlayerMoveFastMoveId;
extern u8 gPlayerMoveVelHandled;
extern u8 gPlayerMoveAdvanced;
extern s16 gPlayerMoveTargetYaw;
extern u8 lbl_803DD44E;
extern u8 lbl_803DD44F;
extern u8 lbl_803DD450;
extern f32 gPlayerMoveOverridePosZ;
extern f32 gPlayerMoveOverridePosX;
extern u32 playerOverride;
extern f32 timeDelta;
extern const f32 lbl_803E0570;
extern const f32 lbl_803E0574;
extern const f32 lbl_803E0578;
extern const f32 lbl_803E057C;
extern const f32 lbl_803E0580;
extern const f32 lbl_803E0584;
extern const f32 lbl_803E0588;
extern const f32 lbl_803E058C;
extern const f32 gPlayerMoveDegToAngle;
extern const f32 lbl_803E0594;
extern const f32 lbl_803E05A0;
extern const f32 gPlayerMovePi;
extern const f32 gPlayerMoveHalfCircleAngle;
extern const f32 lbl_803E05AC;
extern const f32 lbl_803E05B0;
extern const f32 lbl_803E05B4;
extern const f32 lbl_803E05B8;
extern const f32 lbl_803E05BC;
extern const f32 lbl_803E05C0;
extern const f32 lbl_803E05C4;

void dll_0F_func19_nop(void)
{
}

void player_setAnimIds(int unused1, int unused2, u32 a, u32 b)
{
    gPlayerMoveFastMoveId = a;
    gPlayerMoveSlowMoveId = b;
}

void player_clearXZvel(int* obj, int* state)
{
    f32 z = lbl_803E0570;
    ((GameObject*)obj)->anim.velocityX = z;
    ((GameObject*)obj)->anim.velocityZ = z;
    ((BaddieState*)state)->animSpeedC = z;
    ((BaddieState*)state)->animSpeedA = z;
    ((BaddieState*)state)->animSpeedB = z;
}

#pragma scheduling off
#pragma peephole off
void player_playSoundFn0F(int* obj, int* state, int bit, int idx, int* sfxTable)
{
    register int flags;
    register int mask;
    mask = 1 << bit;
    flags = *(int*)&((BaddieState*)state)->eventFlags;
    if ((flags & mask) != 0)
    {
        *(int*)&((BaddieState*)state)->eventFlags = flags & ~mask;
        Sfx_PlayFromObject(obj, (u16)sfxTable[idx]);
    }
}

void player_playSoundFn10(int* obj, int* state, int bit, int idx, int* sfxTable)
{
    register int flags;
    register int mask;
    mask = 1 << bit;
    flags = *(int*)&((BaddieState*)state)->eventFlags;
    if ((flags & mask) != 0)
    {
        *(int*)&((BaddieState*)state)->eventFlags = flags & ~mask;
        Sfx_PlayFromObject(obj, (u16)sfxTable[idx]);
    }
}

void player_render2(s16* obj, int* state, f32 f1, f32 f2)
{
    f32 cur = ((BaddieState*)state)->unk2A8;
    f32 new_ = f2 * f1 + cur;
    if (new_ > lbl_803E0588)
    {
        new_ = lbl_803E0588;
    }
    {
        f32 delta = new_ - cur;
        if (delta > lbl_803E0570)
        {
            *obj += (s16)(((BaddieState*)state)->animDeltaScale * delta);
            ((BaddieState*)state)->unk2A8 = new_;
        }
    }
}

void player_modelMtxFn(f32* mtx, int* state, f32 f1, f32 f2)
{
    f32 cur = ((BaddieState*)state)->speedScale;
    f32 new_ = f2 * f1 + cur;
    if (new_ > lbl_803E0588)
    {
        new_ = lbl_803E0588;
    }
    {
        f32 delta = new_ - cur;
        if (delta > lbl_803E0570)
        {
            *(f32*)((char*)mtx + 12) = *(f32*)((char*)state + 756) * delta + *(f32*)((char*)mtx + 12);
            *(f32*)((char*)mtx + 16) = *(f32*)((char*)state + 760) * delta + *(f32*)((char*)mtx + 16);
            *(f32*)((char*)mtx + 20) = ((BaddieState*)state)->pathStep * delta + *(f32*)((char*)mtx + 20);
            ((BaddieState*)state)->speedScale = new_;
        }
    }
}

#pragma optimization_level 1
void player_findCurve(int* obj, int* state, int p3)
{
    f32 px = ((GameObject*)obj)->anim.localPosX;
    f32 py = ((GameObject*)obj)->anim.localPosY;
    f32 pz = ((GameObject*)obj)->anim.localPosZ;
    *(int*)((char*)state + 0x33c) =
        (*gRomCurveInterface)->find(&p3, 1, *(s8*)((char*)state + 0x344),
                                    px, py, pz);
}
#pragma optimization_level reset

void dll_0F_func0B(int* obj, int* state, f32 f1, f32 f2, f32 f3)
{
    if (*(f32*)((char*)state + 664) > lbl_803E05B4)
    {
        f32 q = (f2 * f1) / f3;
        ((GameObject*)obj)->anim.rotX = (f32) * (s16*)obj + lbl_803E05B8 * q;
    }
}

void player_updateCurve(int* obj, int* state, f32 t)
{
    int idx = *(int*)((char*)state + 828);
    if (idx == -1)
    {
        *(f32*)((char*)state + 700) = lbl_803E0570;
    }
    else
    {
        int* curve = (int*)(*gRomCurveInterface)->getById(idx);
        if (curve == NULL)
        {
            *(f32*)((char*)state + 700) = lbl_803E0570;
        }
        else
        {
            player_followCurve(obj, state, ((ObjfsaRomCurveDef*)curve)->x, ((ObjfsaRomCurveDef*)curve)->z, t, 1);
        }
    }
}

#pragma opt_common_subs off
void player_followCurve(int* obj, int* state, f32 cx, f32 cz, f32 t, int p5)
{
    f32 dx, dz, dist, max;

    *(u32*)state &= ~0x100000;
    dx = ((GameObject*)obj)->anim.localPosX - cx;
    dz = ((GameObject*)obj)->anim.localPosZ - cz;
    dist = sqrtf(dx * dx + dz * dz);
    *(f32*)((char*)state + 0x2bc) = dist;
    max = lbl_803E0578;
    if (*(f32*)((char*)state + 0x2bc) < lbl_803E0580)
    {
        max = lbl_803E0584 * *(f32*)((char*)state + 0x2bc);
        ((BaddieState*)state)->animSpeedC = ((BaddieState*)state)->animSpeedC * lbl_803E0574;
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
    if (((BaddieState*)state)->moveInputX > lbl_803E0578)
    {
        ((BaddieState*)state)->moveInputX = lbl_803E0578;
    }
    if (((BaddieState*)state)->moveInputX < lbl_803E057C)
    {
        ((BaddieState*)state)->moveInputX = lbl_803E057C;
    }
    if (((BaddieState*)state)->moveInputZ > lbl_803E0578)
    {
        ((BaddieState*)state)->moveInputZ = lbl_803E0578;
    }
    if (((BaddieState*)state)->moveInputZ < lbl_803E057C)
    {
        ((BaddieState*)state)->moveInputZ = lbl_803E057C;
    }
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
void dll_0F_func13(s16* obj, int* state, int angle, f32 t, f32 scale)
{
    f32 ang, vx, vz, q, w, dist, c, s;

    *(s8*)((char*)state + 0x34c) |= 1;
    if ((s8)gPlayerMoveVelHandled == 0)
    {
        ang = (gPlayerMovePi * angle) / gPlayerMoveHalfCircleAngle;
        vx = scale * (((BaddieState*)state)->inputMagnitude * -mathSinf(ang));
        vz = scale * (((BaddieState*)state)->inputMagnitude * -mathCosf(ang));
        if (((BaddieState*)state)->inputMagnitude < lbl_803E05AC)
        {
            vx = lbl_803E0570;
            vz = vx;
        }
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX
            + (t * (vx - ((GameObject*)obj)->anim.velocityX)) / ((BaddieState*)state)->velSmoothTime;
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ
            + (t * (vz - ((GameObject*)obj)->anim.velocityZ)) / ((BaddieState*)state)->velSmoothTime;
    }
    else
    {
        *(s8*)((char*)state + 0x34c) &= ~1;
    }
    q = ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX;
    w = ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ;
    dist = sqrtf(q + w);
    ((BaddieState*)state)->animSpeedC = dist;
    if (((BaddieState*)state)->animSpeedC < lbl_803E05B0)
    {
        f32 z = lbl_803E0570;
        ((BaddieState*)state)->animSpeedC = z;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
    c = mathSinf((gPlayerMovePi * (f32) * obj) / gPlayerMoveHalfCircleAngle);
    s = mathCosf((gPlayerMovePi * (f32) * obj) / gPlayerMoveHalfCircleAngle);
    ((BaddieState*)state)->animSpeedB = ((GameObject*)obj)->anim.velocityX * s - ((GameObject*)obj)->anim.velocityZ * c;
    ((BaddieState*)state)->animSpeedA = -((GameObject*)obj)->anim.velocityZ * s - ((GameObject*)obj)->anim.velocityX *
        c;
}
#pragma opt_common_subs reset

#pragma peephole reset
void player_updateParticles(int* p1, int p2, int p3, int count, int mode)
{
    while (count != 0 && p1 != NULL)
    {
        if (mode == 0)
        {
            (*gPartfxInterface)->spawnObject(p1, p3, NULL, 2, -1, NULL);
        }
        else if (mode == 1)
        {
            (*gPartfxInterface)->spawnObject(p1, p3, NULL, 2, -1, NULL);
        }
        else if (mode == 2)
        {
            (*gPartfxInterface)->spawnObject(p1, p3, NULL, 4, -1, NULL);
        }
        count--;
    }
}

void player_doProjGfx(int* p1, int p2, int p3, int count, int p5, int mode)
{
    void* res = Resource_Acquire((u16)(p3 + 0x58), 1);
    while (count != 0)
    {
        if (mode == 0)
        {
            (*(void (*)(int*, int, int, int, int, int))(*(int*)(*(int*)res + 4)))(p1, 0, 0, 1, -1, 0);
        }
        else if (mode == 1)
        {
            (*(void (*)(int*, int, int, int, int, int))(*(int*)(*(int*)res + 4)))(p1, 0, 0, 2, -1, 0);
        }
        else if (mode == 2)
        {
            (*(void (*)(int*, int, int, int, int, int))(*(int*)(*(int*)res + 4)))(p1, 0, 0, 4, -1, 0);
        }
        count--;
    }
    Resource_Release(res);
}

#pragma opt_common_subs off
#pragma peephole off
void player_rotateTowardEnemy(int* obj, int* ctx, int spd)
{
    int* enemy;
    f32 dx;
    f32 dz;
    int diff;
    enemy = (int*)((BaddieState*)ctx)->targetObj;
    if (enemy != 0)
    {
        if ((u32)enemy[0x30 / 4] == obj[0x30 / 4])
        {
            dx = *(f32*)((char*)enemy + 0xc) - ((GameObject*)obj)->anim.localPosX;
            dz = *(f32*)((char*)enemy + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        }
        else
        {
            dx = ((GameObject*)obj)->anim.worldPosX - *(f32*)((char*)enemy + 0x18);
            dz = ((GameObject*)obj)->anim.worldPosZ - *(f32*)((char*)enemy + 0x20);
        }
        diff = (u16)getAngle(-dx, -dz) - (u16)((GameObject*)obj)->anim.rotX;
        if (diff > 0x8000)
        {
            diff -= 0xffff;
        }
        if (diff < -0x8000)
        {
            diff += 0xffff;
        }
        ((GameObject*)obj)->anim.rotX =
            (s16)(((GameObject*)obj)->anim.rotX +
                (int)((f32)diff * timeDelta / (lbl_803E0584 * spd)));
    }
}
#pragma opt_common_subs reset

struct PartDesc
{
    s16 ang[3];
    f32 sc[4];
};
void player_applyVelocityStep(int* p, int* ctx, f32 t)
{
    int flags;
    int b;
    struct PartDesc desc;
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
        ((GameObject*)p)->anim.velocityY = ((GameObject*)p)->anim.velocityY * lbl_803E058C;
        ((GameObject*)p)->anim.velocityY =
            -(((BaddieState*)ctx)->gravity * t) + ((GameObject*)p)->anim.velocityY;
    }
    b = *(s8*)((char*)ctx + 0x34c);
    if ((b & 1) == 0 || (b & 4) != 0)
    {
        desc.ang[0] = ((GameObject*)p)->anim.rotX;
        desc.ang[1] = ((GameObject*)p)->anim.rotY;
        desc.ang[2] = 0;
        desc.sc[0] = lbl_803E0588;
        desc.sc[1] = lbl_803E0570;
        desc.sc[2] = lbl_803E0570;
        desc.sc[3] = lbl_803E0570;
        setMatrixFromObjectPos(mtx, &desc);
        if ((ctx[0] & 0x10000) != 0)
        {
            Matrix_TransformPoint(mtx, ((BaddieState*)ctx)->animSpeedB, *(f32*)((char*)ctx + 0x288),
                                  -((BaddieState*)ctx)->animSpeedA, &outX, &((GameObject*)p)->anim.velocityY,
                                  &outZ);
        }
        else
        {
            Matrix_TransformPoint(mtx, ((BaddieState*)ctx)->animSpeedB, lbl_803E0570,
                                  -((BaddieState*)ctx)->animSpeedA, &outX, &outY, &outZ);
        }
        ((GameObject*)p)->anim.velocityX = outX;
        ((GameObject*)p)->anim.velocityZ = outZ;
    }
    objMove(p, ((GameObject*)p)->anim.velocityX * t, ((GameObject*)p)->anim.velocityY * t,
            ((GameObject*)p)->anim.velocityZ * t);
}

#pragma opt_propagation off
void fn_800D8414(int* obj, int* ctx)
{
    int diff;
    *(f32*)&((BaddieState*)ctx)->trackedObj = ((BaddieState*)ctx)->inputMagnitude;
    ((BaddieState*)ctx)->inputMagnitude =
        sqrtf(((BaddieState*)ctx)->moveInputX * ((BaddieState*)ctx)->moveInputX +
            ((BaddieState*)ctx)->moveInputZ * ((BaddieState*)ctx)->moveInputZ);
    if (((BaddieState*)ctx)->inputMagnitude > lbl_803E0578)
    {
        ((BaddieState*)ctx)->inputMagnitude = *(f32 *)&lbl_803E0578;
    }
    ((BaddieState*)ctx)->inputMagnitude = ((BaddieState*)ctx)->inputMagnitude / lbl_803E0578;
    gPlayerMoveTargetYaw = getAngle(((BaddieState*)ctx)->moveInputX, -((BaddieState*)ctx)->moveInputZ);
    gPlayerMoveTargetYaw = (s16)(gPlayerMoveTargetYaw - ((BaddieState*)ctx)->cameraYaw);
    diff = gPlayerMoveTargetYaw - (u16)((GameObject*)obj)->anim.rotX;
    if (diff > 0x8000)
    {
        diff -= 0xffff;
    }
    if (diff < -0x8000)
    {
        diff += 0xffff;
    }
    *(s16*)&((BaddieState*)ctx)->turnRate = ((f32)diff / gPlayerMoveDegToAngle);
    if (diff < 0)
    {
        *(s16*)((char*)ctx + 0x334) = -((BaddieState*)ctx)->turnRate;
    }
    else
    {
        *(s16*)((char*)ctx + 0x334) = ((BaddieState*)ctx)->turnRate;
    }
    diff += 0x10000;
    if (((BaddieState*)ctx)->inputMagnitude < lbl_803E0594)
    {
        *(u8*)((char*)ctx + 0x34b) = 0;
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
        *(u8*)((char*)ctx + 0x34b) = (u8)(4 - diff / 0x4000);
    }
}
#pragma opt_propagation reset
#pragma opt_common_subs off
void player_getExtraSize(int* a, int* ctx, f32 px, f32 pz, f32 lo, f32 hi, f32 spd)
{
    f32 dx;
    f32 dz;
    f32 mag;
    dx = *(f32*)((char*)a + 0xc) - px;
    dz = *(f32*)((char*)a + 0x14) - pz;
    mag = sqrtf(dx * dx + dz * dz);
    *(f32*)((char*)ctx + 0x2bc) = mag;
    if (lbl_803E0570 != mag)
    {
        dx = dx / mag;
        dz = dz / mag;
    }
    if (*(f32*)((char*)ctx + 0x2bc) > lo + hi)
    {
        ((BaddieState*)ctx)->moveInputX = dx * spd;
        ((BaddieState*)ctx)->moveInputZ = -dz * spd;
    }
    else
    {
        ((BaddieState*)ctx)->animSpeedC = ((BaddieState*)ctx)->animSpeedC * lbl_803E0574;
        ((BaddieState*)ctx)->moveInputZ = ((BaddieState*)ctx)->moveInputX = lbl_803E0570;
    }
    if (((BaddieState*)ctx)->moveInputX > lbl_803E0578)
    {
        ((BaddieState*)ctx)->moveInputX = lbl_803E0578;
    }
    if (((BaddieState*)ctx)->moveInputX < lbl_803E057C)
    {
        ((BaddieState*)ctx)->moveInputX = lbl_803E057C;
    }
    if (((BaddieState*)ctx)->moveInputZ > lbl_803E0578)
    {
        ((BaddieState*)ctx)->moveInputZ = lbl_803E0578;
    }
    if (((BaddieState*)ctx)->moveInputZ < lbl_803E057C)
    {
        ((BaddieState*)ctx)->moveInputZ = lbl_803E057C;
    }
}
#pragma opt_common_subs reset
#pragma opt_common_subs off
void player_animFn16(int* obj, int* ctx, int moveA, int moveB)
{
    f32 mag;
    f32 tmp;
    f32 q1, q2;
    f64 ratio;
    int idx;
    if ((s8)gPlayerMoveVelHandled != 0)
    {
        f32 speedA = ((BaddieState*)ctx)->animSpeedA;
        if (speedA > lbl_803E0570 && ((GameObject*)obj)->anim.currentMove != (int)gPlayerMoveFastMoveId)
        {
            ObjAnim_SetCurrentMove((int)obj, gPlayerMoveFastMoveId, ((GameObject*)obj)->anim.currentMoveProgress, 0);
            ((BaddieState*)ctx)->moveDone = 0;
        }
        else if (speedA < lbl_803E0570 && ((GameObject*)obj)->anim.currentMove != (int)
            gPlayerMoveSlowMoveId)
        {
            ObjAnim_SetCurrentMove((int)obj, gPlayerMoveSlowMoveId, ((GameObject*)obj)->anim.currentMoveProgress, 0);
            ((BaddieState*)ctx)->moveDone = 0;
        }
        q1 = ((BaddieState*)ctx)->animSpeedA * ((BaddieState*)ctx)->animSpeedA;
        q2 = ((BaddieState*)ctx)->animSpeedB * ((BaddieState*)ctx)->animSpeedB;
        mag = sqrtf(q1 + q2);
        if (ObjAnim_SampleRootCurvePhase(mag, (ObjAnimComponent*)obj, &tmp) != 0)
        {
            ((BaddieState*)ctx)->moveSpeed = tmp;
        }
        tmp = (lbl_803E0570 != mag) ? ((BaddieState*)ctx)->animSpeedB / mag : lbl_803E0570;
        ratio = tmp;
        idx = (int)(lbl_803E05A0 * (f32)ratio);
        if (idx < 0)
        {
            idx = -idx;
        }
        if ((f32)idx > lbl_803E05A0)
        {
            idx = 0x4000;
        }
        if (((BaddieState*)ctx)->animSpeedB > lbl_803E0570)
        {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, moveB, idx);
        }
        else
        {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, moveA, idx);
        }
    }
}
#pragma opt_common_subs reset

typedef struct PlayerMoveBuf
{
    f32 a;
    f32 b;
    f32 c;
    u8 pad_0C[2];
    s16 angleDelta;
    u8 pad_10[2];
    u8 flag;
    s8 ids[8];
    s8 count;
} PlayerMoveBuf;

void player_setScale(short* moveState, u32* obj, f32 dt, int flags)
{
    PlayerMoveBuf buf;
    s8* ptr;
    int i;
    f32 stopVal;

    buf.flag = 0;
    *(s8*)&((BaddieState*)obj)->moveDone = ObjAnim_AdvanceCurrentMove(
        ((BaddieState*)obj)->moveSpeed, dt, (int)moveState, (ObjAnimEventList*)&buf);

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
                *(f32*)((char*)obj + 0x2b4) = -buf.c;
            }
            if ((flags & 2) != 0)
            {
                *(f32*)((char*)obj + 0x2b4) = buf.a;
            }
            if ((flags & 4) != 0)
            {
                *(f32*)((char*)obj + 0x2b4) = buf.b;
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
                *(f32*)((char*)obj + 0x288) = buf.b / dt;
                *obj |= 0x10000;
            }
        }
    }
    else
    {
        stopVal = lbl_803E0570;
        ((BaddieState*)obj)->animSpeedA = stopVal;
        ((BaddieState*)obj)->animSpeedB = stopVal;
    }

    gPlayerMoveAdvanced = 1;
}

#pragma scheduling reset
#pragma peephole reset
void player_release(void)
{
}

void player_initialise(void)
{
}

void player_setOverride(u32 x) { playerOverride = x; }

#pragma scheduling off
#pragma peephole off
void player_init(int unused, void* obj, int a, int b)
{
    memset(obj, 0, 0x35c);
    *(s16*)((char*)obj + 0x26c) = a;
    *(s16*)((char*)obj + 0x26e) = b;
    ((BaddieState*)obj)->moveJustStartedA = 1;
    ((BaddieState*)obj)->moveJustStartedB = 1;
    ((BaddieState*)obj)->velSmoothTime = lbl_803E05BC;
    *(s32*)((char*)obj + 0x33c) = -1;
    *(s32*)((char*)obj + 0x340) = -1;
    *(u8*)((char*)obj + 0x358) = 0;
}

void playerRunStateMachine(char* pos, char* state, float dt, int stateFns)
{
    int iterations;
    int currentState;
    int done;
    int result;
    void (*exitFn)(char*, char*);
    int changed;

    changed = 0;
    iterations = 0;
    lbl_803DD450 = 0;
    gPlayerMoveAdvanced = 0;

    if (((BaddieState*)state)->controlMode != ((BaddieState*)state)->unk276)
    {
        ((BaddieState*)state)->moveJustStartedA = 1;
        *(s16*)(state + 0x338) = 0;
    }

    do
    {
        done = 0;
        currentState = ((BaddieState*)state)->controlMode;
        result = (*(int (**)(char*, char*, f32))(stateFns + currentState * 4))(pos, state, dt);
        if (result > 0)
        {
            ((BaddieState*)state)->unk276 = ((BaddieState*)state)->controlMode;
            ((BaddieState*)state)->controlMode = (s16)(result - 1);
            exitFn = *(void (**)(char*, char*))(state + 0x304);
            if (exitFn != NULL)
            {
                exitFn(pos, state);
                *(void**)(state + 0x304) = 0;
            }
            *(void**)(state + 0x304) = *(void**)(state + 0x308);
            ((BaddieState*)state)->moveJustStartedA = 1;
            *(s16*)(state + 0x338) = 0;
            ((BaddieState*)state)->unk34D = 0;
            *(u8*)(state + 0x34c) = 0;
            ((BaddieState*)state)->moveEventFlags = 0;
            *(s16*)(state + 0x278) = 0;
            if (*(void**)(pos + 0x54) != NULL)
            {
                *(u8*)((char*)*(void**)(pos + 0x54) + 0x70) = 0;
            }
        }
        else if (result < 0)
        {
            result = -result;
            ((BaddieState*)state)->controlMode = result;
            if (result != currentState)
            {
                ((BaddieState*)state)->unk276 = (s16)currentState;
                exitFn = *(void (**)(char*, char*))(state + 0x304);
                if (exitFn != NULL)
                {
                    exitFn(pos, state);
                    *(void**)(state + 0x304) = 0;
                }
                *(void**)(state + 0x304) = *(void**)(state + 0x308);
                ((BaddieState*)state)->moveJustStartedA = 1;
                *(s16*)(state + 0x338) = 0;
                ((BaddieState*)state)->unk34D = 0;
                *(u8*)(state + 0x34c) = 0;
                ((BaddieState*)state)->moveEventFlags = 0;
                *(s16*)(state + 0x278) = 0;
                if (*(void**)(pos + 0x54) != NULL)
                {
                    *(u8*)((char*)*(void**)(pos + 0x54) + 0x70) = 0;
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
    }
    while (done == 0);

    if (changed == 0)
    {
        ((BaddieState*)state)->moveJustStartedA = 0;
    }
    ((BaddieState*)state)->unk276 = ((BaddieState*)state)->controlMode;

    if ((s8)gPlayerMoveAdvanced == 0 && ((s32) * (s8*)(state + 0x34c) & 1) == 0)
    {
        u8 animEvents[0x1c];
        int i;

        animEvents[0x1b] = 0;
        *(s8*)&((BaddieState*)state)->moveDone = ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(
            (int)pos, ((BaddieState*)state)->moveSpeed, dt, (ObjAnimEventList*)animEvents);
        ((BaddieState*)state)->eventFlags = 0;
        for (i = 0; i < (s8)animEvents[0x1b]; i++)
        {
            ((BaddieState*)state)->eventFlags |= 1 << (s32)(s8)
            animEvents[0x13 + i];
        }
        *(u32*)state &= 0xfffeffff;
    }

    if ((*(int*)state & 0x4000) == 0)
    {
        int decay;
        f32 t;

        t = (f32)(int) * (s16*)(pos + 2) * dt;
        decay = (s32)(t * lbl_803E05C0);
        *(s16*)(pos + 2) -= decay;
        t = (f32)(int) * (s16*)(pos + 4) * dt;
        decay = (s32)(t * lbl_803E05C0);
        *(s16*)(pos + 4) -= decay;
    }
}

void player_update(char* pos, char* state, float dt, float pathDt, int stateFns, int auxStateFns)
{
    extern void player_applyVelocityStep(char* pos, char* state, f32 dt);
    extern void fn_800D8414(char* pos, char* state);
    struct
    {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } localTransform;
    f32 matrix[16];
    int keepPathControls;
    int attachment;
    int mapBlock;
    int overrideObj;
    f32 dx;
    f32 dz;
    f32 dist;
    f32 limit;
    f32 ldx;
    f32 ldz;
    void* pathObj;

    keepPathControls = 1;
    lbl_803DD44E = 0;

    attachment = *(int*)&((BaddieState*)state)->targetObj;
    if ((void*)attachment != NULL)
    {
        dx = *(f32*)(attachment + 0xc) - *(f32*)(pos + 0xc);
        dz = *(f32*)(attachment + 0x14) - *(f32*)(pos + 0x14);
        ((BaddieState*)state)->targetDistance = sqrtf(dx * dx + dz * dz);
    }
    else
    {
        ((BaddieState*)state)->targetDistance = lbl_803E0570;
    }

    pathObj = *(void**)(pos + 0xc0);
    if ((*(int*)state & 0x8000) != 0 && pathObj == NULL)
    {
        fn_800D915C((int)pos, (int*)state, dt, (void*)auxStateFns);
        ((BaddieState*)state)->stateTimer = (s16)((f32)((BaddieState*)state)->stateTimer + dt);
        if ((f32)((BaddieState*)state)->stateTimer > lbl_803E05C4)
        {
            ((BaddieState*)state)->stateTimer = 10000;
        }
    }

    *(u32*)state |= 0x8000;

    if (*(void**)(state + 0x27c) != NULL)
    {
        localTransform.rotX = *(s16*)(pos + 0);
        localTransform.rotY = *(s16*)(pos + 2);
        localTransform.rotZ = *(s16*)(pos + 4);
        localTransform.scale = lbl_803E0588;
        localTransform.x = lbl_803E0570;
        localTransform.y = lbl_803E0570;
        localTransform.z = lbl_803E0570;
        setMatrixFromObjectPos(matrix, &localTransform);

        attachment = *(int*)(state + 0x27c);
        Matrix_TransformPoint(matrix, lbl_803E0570, *(f32*)&lbl_803E0570, lbl_803E0588,
                              (f32*)(attachment + 0x0), (f32*)(attachment + 0x4), (f32*)(attachment + 0x8));
        attachment = *(int*)(state + 0x27c);
        Matrix_TransformPoint(matrix, lbl_803E0570, lbl_803E0588, *(f32*)&lbl_803E0570,
                              (f32*)(attachment + 0xc), (f32*)(attachment + 0x10), (f32*)(attachment + 0x14));
        attachment = *(int*)(state + 0x27c);
        Matrix_TransformPoint(matrix, lbl_803E0588, lbl_803E0570, *(f32*)&lbl_803E0570,
                              (f32*)(attachment + 0x18), (f32*)(attachment + 0x1c), (f32*)(attachment + 0x20));
    }

    if ((*(int*)state & 0x1000000) == 0)
    {
        fn_800D8414(pos, state);
    }

    *(u32*)state &= 0xffdfffff;
    ((BaddieState*)state)->unk34D = 0;
    gPlayerMoveVelHandled = 0;
    *(u32*)state &= 0xfff7ffff;
    *(u8*)(state + 0x34c) = 0;
    lbl_803DD44F = 0;

    playerRunStateMachine(pos, state, dt, stateFns);

    *(s16*)(state + 0x338) = (s16)((f32) * (s16*)(state + 0x338) + dt);
    if ((f32) * (s16*)(state + 0x338) > lbl_803E05C4)
    {
        *(s16*)(state + 0x338) = 10000;
    }

    gPlayerMoveOverridePosX = *(f32*)(pos + 0xc);
    gPlayerMoveOverridePosZ = *(f32*)(pos + 0x14);
    mapBlock = objPosToMapBlockIdx(*(f32*)(pos + 0x18), *(f32*)(pos + 0x1c), *(f32*)(pos + 0x20));
    if (mapBlock == -1 && *(void**)(pos + 0x30) == NULL)
    {
        *(u32*)state |= 0x200000;
        keepPathControls = 0;
    }

    if ((*(int*)state & 0x1000000) == 0)
    {
        player_applyVelocityStep(pos, state, dt);
    }

    overrideObj = playerOverride;
    if ((void*)overrideObj != NULL)
    {
        dx = *(f32*)(overrideObj + 0xc) - gPlayerMoveOverridePosX;
        dz = *(f32*)(overrideObj + 0x14) - gPlayerMoveOverridePosZ;
        dist = sqrtf(dx * dx + dz * dz);
        if (dist < lbl_803E05BC)
        {
            ldx = *(f32*)(pos + 0xc) - gPlayerMoveOverridePosX;
            ldz = *(f32*)(pos + 0x14) - gPlayerMoveOverridePosZ;
            limit = sqrtf(ldx * ldx + ldz * ldz);
            if (limit < lbl_803E05B4)
            {
                limit = lbl_803E05B4;
            }

            if (dist < lbl_803E0588)
            {
                *(f32*)(pos + 0xc) = *(f32*)(overrideObj + 0xc);
                *(f32*)(pos + 0x14) = *(f32*)(overrideObj + 0x14);
            }
            else
            {
                if (limit > dist)
                {
                    limit = dist;
                }
                dx = dx / dist;
                dz = dz / dist;
                *(f32*)(pos + 0xc) = dx * limit + gPlayerMoveOverridePosX;
                *(f32*)(pos + 0x14) = dz * limit + gPlayerMoveOverridePosZ;
            }
        }
    }

    playerOverride = 0;

    if ((*(int*)state & 0x1000000) == 0 && (*(int*)state & 0x400000) == 0 && keepPathControls != 0)
    {
        (*gPathControlInterface)->update(pos, state + 0x4, dt);
        (*gPathControlInterface)->apply(pos, state + 0x4);
        (*gPathControlInterface)->advance(pos, state + 0x4, pathDt);

        if (((s32) * (s8*)(state + 0x264) & 0x10) != 0)
        {
            *(u32*)state |= 0x40000;
        }
        else
        {
            *(u32*)state &= 0xfffbffff;
        }

        if ((*(int*)state & 0x800000) != 0)
        {
            if (((s32) * (s8*)(state + 0x264) & 2) != 0 || *(u8*)(state + 0x262) != 0)
            {
                *(f32*)(pos + 0x24) = (*(f32*)(pos + 0xc) - *(f32*)(*(int*)(pos + 0x54) + 0x10)) / dt;
                *(f32*)(pos + 0x2c) = (*(f32*)(pos + 0x14) - *(f32*)(*(int*)(pos + 0x54) + 0x18)) / dt;
            }
            *(u32*)state &= 0xff7fffff;
        }
    }
}

void player_updateVel(char* p, char* obj, int unused)
{
    float fcos, fsin;
    if (((s32)(s8) * (obj + 0x34c) & 1) != 0)
    {
        fcos = mathSinf(gPlayerMovePi * (float)(s32) * (s16*)p / gPlayerMoveHalfCircleAngle);
        fsin = mathCosf(gPlayerMovePi * (float)(s32) * (s16*)p / gPlayerMoveHalfCircleAngle);
        if (((s32)(s8) * (obj + 0x34c) & 8) != 0)
        {
            ((BaddieState*)obj)->animSpeedA = -((GameObject*)p)->anim.velocityZ * fsin - ((GameObject*)p)->anim.velocityX * fcos;
            ((BaddieState*)obj)->animSpeedC = ((BaddieState*)obj)->animSpeedA;
        }
        else
        {
            ((BaddieState*)obj)->animSpeedB = ((GameObject*)p)->anim.velocityX * fsin - ((GameObject*)p)->anim.velocityZ * fcos;
            ((BaddieState*)obj)->animSpeedA = -((GameObject*)p)->anim.velocityZ * fsin - ((GameObject*)p)->anim.velocityX * fcos;
            if (((s32)(s8) * (obj + 0x34c) & 4) != 0)
            {
                ((BaddieState*)obj)->animSpeedC = sqrtf(((GameObject*)p)->anim.velocityX * ((GameObject*)p)->anim.velocityX +
                    ((GameObject*)p)->anim.velocityZ * ((GameObject*)p)->anim.velocityZ);
            }
        }
        *(s8*)(obj + 0x34c) = 0;
        *(u32*)obj |= 0x80000;
        gPlayerMoveVelHandled = 1;
        lbl_803DD44F = 0;
        lbl_803DD44E = 1;
        playerRunStateMachine(p, obj, timeDelta, unused);
    }
}

void player_setState(void* ctx, void* p, int new_state)
{
    void* q;
    if (((BaddieState*)p)->controlMode == new_state) goto end;
    ((BaddieState*)p)->unk276 = ((BaddieState*)p)->controlMode;
    ((BaddieState*)p)->controlMode = new_state;
    {
        void (*fn)(void) = *(void (**)(void))((char*)p + 0x304);
        if (fn != 0)
        {
            fn();
            *(void**)&((BaddieState*)p)->unk304 = 0;
        }
    }
    *(void**)&((BaddieState*)p)->unk304 = *(void**)&((BaddieState*)p)->unk308;
end:
    *(s16*)((char*)p + 0x338) = 0;
    ((BaddieState*)p)->moveJustStartedA = 1;
    ((BaddieState*)p)->unk34D = 0;
    *(u8*)((char*)p + 0x34c) = 0;
    ((BaddieState*)p)->moveEventFlags = 0;
    *(s16*)((char*)p + 0x278) = 0;
    q = *(void**)((char*)ctx + 0x54);
    if (q != 0) *(u8*)((char*)q + 0x70) = 0;
}

void fn_800D915C(int p1, int* obj, f32 fval, void* fnTable)
{
    int i;
    s16 startState;
    int done;
    int result;
    int flag30;
    flag30 = 0;
    i = 0;
    if (((BaddieState*)obj)->substate != ((BaddieState*)obj)->prevSubstate)
    {
        ((BaddieState*)obj)->moveJustStartedB = 1;
        ((BaddieState*)obj)->stateTimer = 0;
    }
    do
    {
        done = 0;
        startState = ((BaddieState*)obj)->substate;
        result = ((int (*)(int, int*, f32))((int**)fnTable)[startState])(p1, obj, fval);
        if (result > 0)
        {
            ((BaddieState*)obj)->prevSubstate = ((BaddieState*)obj)->substate;
            ((BaddieState*)obj)->substate = result - 1;
            ((BaddieState*)obj)->moveJustStartedB = 1;
            ((BaddieState*)obj)->stateTimer = 0;
        }
        else if (result < 0)
        {
            result = -result;
            if (result != startState)
            {
                ((BaddieState*)obj)->prevSubstate = (s16)(int)startState;
                ((BaddieState*)obj)->moveJustStartedB = 1;
                ((BaddieState*)obj)->stateTimer = 0;
            }
            else
            {
                ((BaddieState*)obj)->moveJustStartedB = 0;
            }
            ((BaddieState*)obj)->substate = result;
            done = 1;
            flag30 = 1;
        }
        else
        {
            done = 1;
        }
        i++;
        if (i > 0xff)
        {
            done = 1;
        }
    }
    while (done == 0);
    ((BaddieState*)obj)->prevSubstate = ((BaddieState*)obj)->substate;
    if (flag30 == 0)
    {
        ((BaddieState*)obj)->moveJustStartedB = 0;
        if ((f32) * (s16*)((char*)obj + 0x338) > lbl_803E05BC)
        {
            ((BaddieState*)obj)->moveJustStartedB = 0;
        }
    }
}
