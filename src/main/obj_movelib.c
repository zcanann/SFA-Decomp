/*
 * Shared object movement / effect toolkit.
 *
 * A grab-bag of GameObject helpers linked into the main DOL and consumed by
 * the Drakor-area DLLs (bossdrakor, drakorhoverpad, drbarrelgr, drcloudrunner,
 * drlasercannon, hightop), babycloudrunner and the ArwingSquadron DLL: a
 * lightning-cluster spawner, a ballistic intercept predictor, voxel
 * world-line trace wrappers, a hit-light spawner, a velocity steering
 * integrator, the RomCurve follow-velocity drivers and a heading/roll/pitch
 * smoother.
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "main/model_light.h"
#include "main/voxmaps.h"
#include "main/shader_api.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/rom_curve_def.h"
#include "main/maketex_timer_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/barrelgener_state.h"
#include "game/objects/object.h"
#include "sys/objects.h"
#include "main/newclouds.h"
#include "dolphin/mtx/vec.h"
#include "main/objfx.h"
#include "main/dll/baddie_state.h"
#include "main/dll/partfx_interface.h"
#include "main/curve.h"
#include "main/vecmath.h"

f32 gObjLightningClusterRadiusX = 2.0f;
f32 gObjLightningClusterRadiusY = 0.2f;
f32 gObjLightningClusterLifetime = 20.0f;
u16 gObjLightningClusterWidth = 0x40;

int Obj_UpdateLightningCluster(GameObject* obj, LightningEffect** entries, int count, f32 intensity,
                               ModelLight** light)
{
    int spawned;
    int i;
    f32 pos[3];

    spawned = 0;
    if (intensity == 0.0f)
    {
        spawned = 0;
        for (i = 0; i < count; i++)
        {
            if (entries[i] != 0)
            {
                mm_free_(entries[i]);
                entries[i] = 0;
            }
        }
        if (*light != 0)
        {
            modelLightStruct_freeSlot(light);
        }
        return 0;
    }

    for (i = 0; i < count; i++)
    {
        if (entries[i] != 0)
        {
            lightningRender(entries[i]);
            entries[i]->timer += framesThisStep;
            if ((f32)(u32)entries[i]->timer > gObjLightningClusterLifetime)
            {
                mm_free_(entries[i]);
                entries[i] = 0;
            }
        }
        else if (spawned == 0)
        {
            pos[0] = obj->anim.localPosX;
            pos[1] = obj->anim.localPosY;
            pos[2] = obj->anim.localPosZ;
            pos[0] += 0.001f * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            pos[1] += 0.001f * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            pos[2] += 0.001f * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            entries[i] =
                lightningCreate((const Vec3f*)&obj->anim.localPosX, (const Vec3f*)pos, gObjLightningClusterRadiusX,
                                           gObjLightningClusterRadiusY, gObjLightningClusterLifetime, gObjLightningClusterWidth, 0);
            spawned = 1;
        }
    }

    if (*light == 0)
    {
        *light = modelLightStruct_createPointLight(obj, 0x80, 0x80, 0xff, 0);
        if (*light != 0)
        {
            modelLightStruct_setPosition(*light, 0.0f, intensity / 4.0f, 0.0f);
            modelLightStruct_setDistanceAttenuation(*light, intensity, 50.0f + intensity);
        }
    }
    return 1;
}

int Obj_PredictInterceptPoint(GameObject* obj, f32 dt, const Vec3f* targetPos, Vec3f* outPos)
{
    f32 pos[3];
    f32 step[3];
    f32 vel[3];
    int gridOut[2];
    int gridB[2];
    int gridA[2];
    int i;

    if (obj != Obj_GetPlayerObject())
    {
        PSVECSubtract((const Vec*)&(obj)->anim.localPosX, (const Vec*)&(obj)->anim.previousLocalPosX, (Vec*)vel);
    }
    else
    {
        vel[0] = (obj)->anim.velocityX;
        vel[1] = (obj)->anim.velocityY;
        vel[2] = (obj)->anim.velocityZ;
    }
    PSVECScale((const Vec*)vel, (Vec*)vel, oneOverTimeDelta);
    pos[0] = (obj)->anim.localPosX;
    pos[1] = 15.0f + (obj)->anim.localPosY;
    pos[2] = (obj)->anim.localPosZ;
    for (i = 0; i < 5; i++)
    {
        PSVECScale((const Vec*)vel, (Vec*)step,
                   PSVECDistance((const Vec*)pos, (const Vec*)targetPos) / dt);
        PSVECAdd((const Vec*)&obj->anim.localPosX, (const Vec*)step, (Vec*)pos);
    }
    outPos->x = pos[0];
    outPos->y = pos[1];
    outPos->z = pos[2];
    voxmaps_worldToGrid((void*)targetPos, (s16*)gridA);
    voxmaps_worldToGrid(pos, (s16*)gridB);
    return voxmaps_traceLine((VoxPos*)gridA, (VoxPos*)gridB, (VoxPos*)gridOut, NULL, 0) != 0;
}

static f32 Obj_RollFromTurnRate(f32 turn)
{
    return 0.05f * turn;
}

static f32 Obj_HeadingRadians(s16 heading)
{
    return 3.1415927f * (f32)(-heading) / 32768.0f;
}

int voxmaps_traceWorldLine(void* startPos, void* endPos)
{
    int grid1[2];
    int grid2[2];
    int out[2];

    voxmaps_worldToGrid(startPos, (s16*)grid1);
    voxmaps_worldToGrid(endPos, (s16*)grid2);
    return voxmaps_traceLine((VoxPos*)grid1, (VoxPos*)grid2, (VoxPos*)out, NULL, 0);
}

void voxmaps_traceScaledVectorEnd(f32* out, void* origin, f32* dir, f32 scale)
{
    f32 endPos[3];
    f32 scaled[3];
    int gridA[2];
    int gridB[2];
    int gridOut[2];

    PSVECNormalize((const Vec*)dir, (Vec*)dir);
    PSVECScale((const Vec*)dir, (Vec*)scaled, scale);
    PSVECAdd((const Vec*)scaled, (const Vec*)origin, (Vec*)endPos);
    voxmaps_worldToGrid(origin, (s16*)gridA);
    voxmaps_worldToGrid(endPos, (s16*)gridB);
    if (voxmaps_traceLine((VoxPos*)gridA, (VoxPos*)gridB, (VoxPos*)gridOut, NULL, 0) == 0)
        voxmaps_gridToWorld(endPos, (s16*)gridOut);
    *(Vec3f*)out = *(Vec3f*)endPos;
}

void Obj_SpawnHitLightAndFade(GameObject* obj, const Vec3f* pos, f32 scale)
{
    PartFxSpawnParams s;

    s.posX = pos->x + playerMapOffsetX;
    s.posY = pos->y;
    s.posZ = pos->z + playerMapOffsetZ;
    objDoHitParticleFx(obj, 0.014f, &s, 1, 0);
    Obj_SetModelColorFadeRecursive(obj, 0x5a, 0xc8, 0, 0, 1);
}

void Obj_SteerVelocityTowardVector(GameObject* obj, Vec3f* currentVelocity, Vec3f* desiredDirection, f32 maxSpeed,
                                   f32 maxSpeedDelta, f32 maxTurnAngle)
{
    f32 mtx[12];
    f32 n1[3];
    f32 n2[3];
    f32 cross[3];
    f32 mag1, mag2, t, ang;
    int gt;
    f32 gtf;

    mag1 = PSVECMag((const Vec*)currentVelocity);
    if (mag1 > 0.0f)
    {
        f32 inv = 1.0f / mag1;
        n1[0] = currentVelocity->x * inv;
        n1[1] = currentVelocity->y * inv;
        n1[2] = currentVelocity->z * inv;
        PSVECNormalize((const Vec*)n1, (Vec*)n1);
    }
    else
    {
        n1[0] = 0.0f;
        n1[1] = 0.0f;
        n1[2] = 0.0f;
    }
    mag2 = PSVECMag((const Vec*)desiredDirection);
    if (mag2 > 0.0f)
    {
        f32 inv = 1.0f / mag2;
        n2[0] = desiredDirection->x * inv;
        n2[1] = desiredDirection->y * inv;
        n2[2] = desiredDirection->z * inv;
    }
    else
    {
        n2[0] = 0.0f;
        n2[1] = 0.0f;
        n2[2] = 0.0f;
    }
    PSVECCrossProduct((const Vec*)n1, (const Vec*)n2, (Vec*)cross);
    if (PSVECMag((const Vec*)cross) > 0.0f)
    {
        ang = acosf_fast(PSVECDotProduct((const Vec*)n1, (const Vec*)n2));
        gt = (ang > maxTurnAngle);
        gtf = __fabsf((f32)gt);
        if (gtf)
        {
            PSMTXRotAxisRad((MtxP)mtx, (const Vec*)cross,
                            maxTurnAngle * (ang > 0.0f ? 1.0f : -1.0f));
            PSMTXMultVecSR((MtxP)mtx, (const Vec*)n1, (Vec*)n2);
        }
    }
    t = mag2;
    t *= 0.075f;
    if (t > mag1 + maxSpeedDelta)
        t = mag1 + maxSpeedDelta;
    else if (t < mag1 - maxSpeedDelta)
        t = mag1 - maxSpeedDelta;
    if (t > maxSpeed)
        t = maxSpeed;
    obj->anim.velocityX = n2[0] * t;
    obj->anim.velocityY = n2[1] * t;
    obj->anim.velocityZ = n2[2] * t;
}

int Obj_UpdateRomCurveFollowVelocityIndexed(GameObject* obj, RomCurveWalker* route, f32 advanceStep,
                                            f32 arriveRadius, f32 speed, int flag, int* pickIdx)
{
    int result;
    f32 delta[3];
    f32 dist, ang;

    result = 0;
    delta[0] = obj->anim.localPosX - route->posX;
    delta[2] = obj->anim.localPosZ - route->posZ;
    {
        f32 xx = delta[0] * delta[0];
        f32 zz = delta[2] * delta[2];
        dist = sqrtf(xx + zz);
    }
    if (dist < arriveRadius)
    {
        if (Curve_AdvanceAlongPath(&route->curve, advanceStep) != 0 || route->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPointIndexed(route, *pickIdx) != 0)
                result = -1;
            else
                result = ((RomCurveDef*)route->previousNode)->action;
            *pickIdx = 0;
        }
        speed = 2.0f * advanceStep;
    }
    delta[0] = route->posX - obj->anim.localPosX;
    delta[1] = route->posY - obj->anim.localPosY;
    delta[2] = route->posZ - obj->anim.localPosZ;
    if ((u8)flag == 0)
    {
        BaddieState* state = obj->extra;
        s16 raw;
        delta[0] = obj->anim.localPosX - route->posX;
        delta[2] = obj->anim.localPosZ - route->posZ;
        raw = (s16)getAngle(delta[0], delta[2]);
        ang = Obj_HeadingRadians(raw);
        state->moveInputX = speed * -mathSinf(ang);
        state->moveInputZ = speed * -mathCosf(ang);
    }
    else
    {
        Obj_SteerVelocityTowardVector(obj, (Vec3f*)&obj->anim.velocityX, (Vec3f*)delta, speed,
                                      speed / 30.0f, 0.3f);
    }
    return result;
}

int Obj_UpdateRomCurveFollowVelocity(GameObject* obj, RomCurveWalker* route, f32 advanceStep, f32 arriveRadius,
                                     f32 speed, int flag)
{
    int result;
    f32 delta[3];
    f32 dist, ang;

    result = 0;
    delta[0] = obj->anim.localPosX - route->posX;
    delta[2] = obj->anim.localPosZ - route->posZ;
    {
        f32 xx = delta[0] * delta[0];
        f32 zz = delta[2] * delta[2];
        dist = sqrtf(xx + zz);
    }
    if (dist < arriveRadius)
    {
        if (Curve_AdvanceAlongPath(&route->curve, advanceStep) != 0 || route->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(route) != 0)
                result = -1;
            else
                result = ((RomCurveDef*)route->previousNode)->action;
        }
        speed = 2.0f * advanceStep;
    }
    delta[0] = route->posX - obj->anim.localPosX;
    delta[1] = route->posY - obj->anim.localPosY;
    delta[2] = route->posZ - obj->anim.localPosZ;
    if ((u8)flag == 0)
    {
        BaddieState* state = obj->extra;
        s16 raw;
        delta[0] = obj->anim.localPosX - route->posX;
        delta[2] = obj->anim.localPosZ - route->posZ;
        raw = (s16)getAngle(delta[0], delta[2]);
        ang = Obj_HeadingRadians(raw);
        state->moveInputX = speed * -mathSinf(ang);
        state->moveInputZ = speed * -mathCosf(ang);
    }
    else
    {
        Obj_SteerVelocityTowardVector(obj, (Vec3f*)&obj->anim.velocityX, (Vec3f*)delta, speed,
                                      speed / 30.0f, 0.3f);
    }
    return result;
}

void Obj_SmoothTurnAnglesTowardVelocity(GameObject* obj, const Vec3f* velocity, int turnFrames, f32 rollFactor,
                                        f32 pitchFactor)
{
    ObjAnimComponent* anim = &obj->anim;
    f32 rate;
    f32 delta;
    f32 clamped;
    f32 dist;
    int rotZ;

    rate = timeDelta / (f32)(u32)(u16)turnFrames;
    if (rate > 1.0f)
    {
        rate = 1.0f;
    }

    delta = (f32)(int)((u16)getAngle(-velocity->x, -velocity->z) - (u16)anim->rotX);
    if (delta > 32768.0f)
    {
        delta = -65535.0f + delta;
    }
    if (delta < -32768.0f)
    {
        delta = 65535.0f + delta;
    }
    delta *= rate;
    clamped = (delta < -512.0f)
                  ? -512.0f
                  : ((delta > 512.0f) ? 512.0f : delta);
    anim->rotX += (int)clamped;

    if (rollFactor)
    {
        anim->rotZ = (s16)(0.9f * (f32)anim->rotZ);
        anim->rotZ = (s16)(oneOverTimeDelta * Obj_RollFromTurnRate(clamped * rollFactor) + (f32)anim->rotZ);
        rotZ = anim->rotZ;
        if (rotZ < -0x2000)
        {
            rotZ = -0x2000;
        }
        else if (rotZ > 0x2000)
        {
            rotZ = 0x2000;
        }
        anim->rotZ = rotZ;
    }

    if (pitchFactor != 0.0f)
    {
        {
            f32 xx = velocity->x * velocity->x;
            f32 zz = velocity->z * velocity->z;
            dist = sqrtf(xx + zz);
        }
        delta = (f32)(int)((u16)getAngle(velocity->y * pitchFactor, dist) - (u16)anim->rotY);
        if (delta > 32768.0f)
        {
            delta = -65535.0f + delta;
        }
        if (delta < -32768.0f)
        {
            delta = 65535.0f + delta;
        }
        anim->rotY += (int)(delta * rate);
    }
}
