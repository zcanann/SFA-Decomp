/*
 * skeetla - Tricky (the companion dinosaur) movement, collision and
 * route-following AI, stored in the object's TrickyState extra block.
 *
 * Per-frame trickyUpdateCollisionAndPathState snaps Tricky to the ground,
 * applies water buoyancy, processes priority hits (lighting fx, hit sparks,
 * out-of-water bark), then drives the path-control interface and copies the
 * resulting yaw/roll back onto the object. trickyMove steers toward a target
 * point with object-avoidance (trickyApplyObjectAvoidanceToStep) and picks a
 * walk/run/turn anim plus footstep sfx by speed. The RomCurve helpers
 * (trickySelectRouteEntry and friends) choose and walk the spline route
 * Tricky follows, gated by game bits on each curve. skeetla_spawnLinkedSparks
 * emits the contact-spark particles for the object Tricky is linked to.
 */
#include "main/dll/objfsa_romcurve.h"
#include "main/effect_interfaces.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objhits.h"
#include "main/objHitReact.h"
#include "main/objfx.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/dll/objfsa.h"
#include "main/gamebits.h"
#include "main/lightmap.h"

/* Per-node fan-out limit: status[]/bestDistances[]/outRoutes[] hold at most
 * this many linked route candidates (status[8] / f32 bestDistances[8]). */
#define TRICKY_ROUTE_CANDIDATE_COUNT 8

extern const f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23EC;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E2424;
extern f32 lbl_803E2428;
extern f32 lbl_803E242C;
extern f32 lbl_803E2430;
extern f32 lbl_803E2434;
extern f32 lbl_803E2438;
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void hitDetectFn_800658a4(u8* obj, f32 x, f32 y, f32 z, f32* out, int flags);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern void Sfx_PlayFromObject(u8* obj, int sfxId);

extern int ObjGroup_FindNearestObject(int group, u8* obj, f32* outDistance);
extern f32 lbl_803E244C;
extern f32 lbl_803E2448;
extern f32 lbl_803E23F8;
extern f32 lbl_803E2450;
extern f32 getXZDistance(f32* a, f32* b);
extern f32 lbl_803E23E8;
extern f32 lbl_803E2418;
extern f32 lbl_803E2420;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f32 lbl_803E2468;
extern f32 lbl_803E246C;
extern f32 lbl_803E2470;
extern f32 lbl_803E2474;
extern f32 lbl_803E247C;
extern f32 lbl_803E2478;
extern f32 lbl_803E2480;
extern const f32 lbl_803E2484;
extern f32 oneOverTimeDelta;
extern char sSkeetlaVelDebugFmt;
extern char lbl_8031D2E8[];
extern u32 gSkeetlaFootstepSfxIds01;
extern u16 gSkeetlaFootstepSfxId2;
extern s16 getAngle(f32 x, f32 z);
extern int Sfx_IsPlayingFromObjectChannel(u8* obj, int channel);
extern void objAudioFn_800393f8(u8* obj, void* audio, int sfxId, int volume, int param5, int param6);
extern int objAnimFn_8013a3f0(int obj, int newState, f32 speed, u32 flags);
extern void trickyApplyObjectAvoidanceToStep(f32 * start, f32 * end, f32 * guardPoint);
extern void* fn_8004B118(void* search);
extern void fn_8004B148(void* search);
extern void fn_8004B31C(void* search, u32 route, int objId, int pathId, int routeFlags);
extern void* ObjList_GetObjects(int* outA, int* outB);
extern void** ObjGroup_GetObjects(int group, int* countOut);

#pragma peephole off
void trickyUpdateCollisionAndPathState(u8* obj)
{
    TrickyState* state;
    f32 hitOffsetY;
    void* lastContactObj;
    f32 nearestDistance;
    f32 hitPos[3];
    f32 lightArgs[3];
    f32* hitPosPtr;
    u8 doGroundSnap;
    int doHeightSnap;
    int hitKind;

    state = (TrickyState*)((GameObject*)obj)->extra;
    doGroundSnap = 0;
    nearestDistance = lbl_803E2424;

    if ((objPosToMapBlockIdx(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                             ((GameObject*)obj)->anim.worldPosZ) == -1) &&
        ((state->stateFlags & 0x80000) == 0))
    {
        state->unk353 = 0;
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.previousLocalPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.previousLocalPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
    }

    state->stateFlags &= ~0x80000LL;

    if (state->unk374 != 0)
    {
        state->unk374 -= 1;
        doGroundSnap = 1;
    }
    else if ((state->stateFlags & 0x2000) != 0)
    {
        doGroundSnap = 1;
    }

    if (doGroundSnap != 0)
    {
        hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                             ((GameObject*)obj)->anim.worldPosZ, &hitOffsetY, 0);
        ((GameObject*)obj)->anim.localPosY -= hitOffsetY;
        state->unk353 = 0;
    }

    if (((s8)state->unk353 != 0) && (((state->statusFlags >> 5) & 1) == 0u))
    {
        if (lbl_803E23DC == state->waterLevel)
        {
            doHeightSnap = 0;
        }
        else if (lbl_803E2410 == state->unk2B0)
        {
            doHeightSnap = 1;
        }
        else if (state->unk2B4 - state->unk2B0 > lbl_803E2414)
        {
            doHeightSnap = 1;
        }
        else
        {
            doHeightSnap = 0;
        }

        if (doHeightSnap != 0)
        {
            ((GameObject*)obj)->anim.velocityY = *(f32*)&lbl_803E23DC;
            ((GameObject*)obj)->anim.localPosY = state->unk2B4 - lbl_803E23EC;
        }
        else
        {
            ((GameObject*)obj)->anim.velocityY += lbl_803E2428 * timeDelta;
            ((GameObject*)obj)->anim.localPosY += ((GameObject*)obj)->anim.velocityY * timeDelta;
        }
    }
    else
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E23DC;
    }

    lastContactObj = (void*)((GameObject*)obj)->anim.hitReactState->activeHit;
    if ((((GameObject*)obj)->anim.hitReactState->flags & 8) == 0 ||
        (((GameObject*)lastContactObj)->anim.seqId == 0x1f))
    {
        lastContactObj = NULL;
    }

    if ((state->stateFlags & 8) != 0)
    {
        state->contactTimer += timeDelta;
        if (state->contactTimer >= lbl_803E242C)
        {
            if (vec3f_distanceSquared((f32*)(obj + 0x18),
                                      (f32*)(Obj_GetPlayerObject() + 0x18)) > lbl_803E2430)
            {
                state->contactTimer -= lbl_803E242C;
                ((GameObject*)obj)->anim.modelInstance->runtimeSourceHitMask = 0x7f;
                state->stateFlags &= ~8LL;
            }
        }
    }
    else if ((state->lastContactObj != NULL) &&
        (lastContactObj == state->lastContactObj))
    {
        state->contactTimer += timeDelta;
        if (state->contactTimer >= *(f32*)&lbl_803E23E0)
        {
            state->contactTimer -= lbl_803E23E0;
            state->stateFlags |= 8;
            ((GameObject*)obj)->anim.modelInstance->runtimeSourceHitMask = 0x7e;
        }
    }
    else
    {
        state->contactTimer = lbl_803E23DC;
    }

    state->lastContactObj = lastContactObj;
    hitKind = ObjHits_PollPriorityHitWithCooldown((int)obj, &state->hitCooldown,
                                                  (int*)&lastContactObj, (hitPosPtr = hitPos));
    state->light = hitKind;

    switch (state->light)
    {
    case 1:
    case 2:
    case 4:
    case 5:
    case 0xe:
    case 0xf:
    case 0x11:
    case 0x13:
        objLightFn_8009a1dc(obj, lbl_803E2434, lightArgs, 1, 0);
        break;
    case 7:
    case 8:
    case 9:
    case 0xa:
    case 0xb:
    case 0xc:
        objfx_spawnHitEmitterAtPos(hitPosPtr, 8, 0xff, 0x20, 0x20);
        objLightFn_8009a1dc(obj, lbl_803E2434, lightArgs, 4, 0);
        if (((GameObject*)lastContactObj)->anim.seqId == 0x69)
        {
            Sfx_PlayFromObject(obj, SFXfox_outofwater122);
        }
        break;
    case 0x1f:
        state->unk838 = lbl_803E2438;
        break;
    }

    if ((s8)state->unk353 == 0)
    {
        (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
    }

    if ((coordsToMapCell(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ) == 0xe) ||
        ((u32)ObjGroup_FindNearestObject(5, obj, &nearestDistance) != 0u))
    {
        state->pathControlFlags &= ~4;
    }
    else
    {
        state->pathControlFlags |= 4;
    }

    (*gPathControlInterface)->update(obj, &state->pathControlFlags, timeDelta);
    (*gPathControlInterface)->apply(obj, &state->pathControlFlags);
    (*gPathControlInterface)->advance(obj, &state->pathControlFlags, timeDelta);

    ((GameObject*)obj)->anim.rotY = state->pathRotY;
    ((GameObject*)obj)->anim.rotZ = state->pathRotZ;
}

#pragma peephole on
int trickyAdvanceRouteTargetAhead(int obj, RomCurveWalker *route, f32 speed)
{
    f32 limit;
    f32 maxSq, dist, step;
    int iter;
    int result;
    f32 tmp;

    result = 0;
    tmp = lbl_803E244C * (speed * timeDelta);
    maxSq = tmp * tmp;
    dist = getXZDistance(&route->posX, (f32*)(obj + 0x18));
    if (route->reverse != 0)
    {
        step = lbl_803E2448;
    }
    else
    {
        step = lbl_803E23F8;
    }
    iter = 0;
    limit = lbl_803E2424;
    for (; iter < 5; iter++)
    {
        if (dist > limit && maxSq < dist)
        {
            return result;
        }
        result = 1;
        RomCurve_stepClamped(route, step);
        dist = getXZDistance(&route->posX, (f32*)(obj + 0x18));
    }
    return 1;
}

#pragma peephole off
#pragma optimization_level 2
int trickyTurnTowardYaw(u8* obj, s16 targetYaw)
{
    u8* state;
    int currentYaw;
    int delta;
    int step;

    state = ((GameObject*)obj)->extra;
    ((TrickyState*)state)->unk5A = targetYaw;

    delta = (u16)(s16)targetYaw;
    currentYaw = ((GameObject*)obj)->anim.rotX;
    delta = currentYaw - delta;
    if (delta > 0x8000)
    {
        delta -= 0xffff;
    }
    if (delta < -0x8000)
    {
        delta += 0xffff;
    }

    if ((((TrickyState*)state)->stateFlags & 0x100000) != 0)
    {
        ((TrickyState*)state)->stateFlags |= 0x200000LL;
    }
    else
    {
        ((TrickyState*)state)->stateFlags &= ~0x200000LL;
    }
    ((TrickyState*)state)->stateFlags &= 0xef2fffff;

    if (delta > 0x10)
    {
        ((TrickyState*)state)->stateFlags |= 0x900000LL;
    }
    else if (delta < -0x10)
    {
        ((TrickyState*)state)->stateFlags |= 0x500000LL;
    }
    else
    {
        ((GameObject*)obj)->anim.rotX = targetYaw;
        return 0;
    }

    if (delta > 0x200)
    {
        step = (s32)(lbl_803E2450 * timeDelta);
        ((GameObject*)obj)->anim.rotX = currentYaw - step;
        ((TrickyState*)state)->stateFlags |= 0x10000000LL;
    }
    else if (delta < -0x200)
    {
        step = (s32)(lbl_803E2450 * timeDelta);
        ((GameObject*)obj)->anim.rotX = currentYaw + step;
        ((TrickyState*)state)->stateFlags |= 0x10000000LL;
    }
    else
    {
        ((GameObject*)obj)->anim.rotX = targetYaw;
    }

    return delta;
}
#pragma optimization_level reset

#pragma scheduling on
#pragma peephole on
static int skeetla_isInWater(u8* state)
{
    if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
    {
        return 0;
    }
    if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
    {
        return 1;
    }
    if ((((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0) > lbl_803E2414)
    {
        return 1;
    }
    return 0;
}

static f32 skeetla_pathSpeedDelta(u8* obj)
{
    TrickyState* state = (TrickyState*)((GameObject*)obj)->extra;
    f32* currentPathPoint;
    f32 dx;
    f32 dz;
    f32 previousSpeed;
    f32 currentSpeed;

    currentPathPoint = (f32*)state->unk28;
    if ((f32*)state->unk28 == state->previousPathPoint)
    {
        dx = state->previousPathX - ((GameObject*)obj)->anim.worldPosX;
        dz = state->previousPathZ - ((GameObject*)obj)->anim.worldPosZ;
        previousSpeed = oneOverTimeDelta * sqrtf((dx * dx) + (dz * dz));

        dx = currentPathPoint[0] - ((GameObject*)obj)->anim.worldPosX;
        dz = currentPathPoint[2] - ((GameObject*)obj)->anim.worldPosZ;
        currentSpeed = oneOverTimeDelta * sqrtf((dx * dx) + (dz * dz));
        return currentSpeed - previousSpeed;
    }
    return lbl_803E23DC;
}

static void skeetla_updateFacingFromMoveVector(u8* obj, s16* turnDeltaOut)
{
    u8* state;
    f32 dx;
    f32 xx;
    f32 dz;
    f32 zz;
    int yaw;

    state = ((GameObject*)obj)->extra;
    dx = ((TrickyState*)state)->dirX;
    xx = dx * dx;
    dz = ((TrickyState*)state)->dirZ;
    zz = dz * dz;
    if ((xx + zz) > lbl_803E23EC)
    {
        yaw = getAngle(-dx, -dz);
        *turnDeltaOut = trickyTurnTowardYaw(obj, yaw);
        ((TrickyState*)state)->dirX = -mathSinf((lbl_803E2454 * (f32)(int) * (s16*)obj) / lbl_803E2458);
        ((TrickyState*)state)->dirZ = -mathCosf((lbl_803E2454 * (f32)(int) * (s16*)obj) / lbl_803E2458);
    }
}

static void skeetla_playFootstepSfx(u8* obj, u16 sfxId)
{
    u8* state = ((GameObject*)obj)->extra;
    if (((((TrickyState*)((GameObject*)obj)->extra)->statusFlags >> 6) & 1) == 0u &&
        ((((GameObject*)obj)->anim.currentMove >= 0x30) || (((GameObject*)obj)->anim.currentMove < 0x29)) &&
        (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0))
    {
        objAudioFn_800393f8(obj, state + 0x3a8, sfxId, 0x500, -1, 0);
    }
}

#pragma scheduling off
#pragma peephole off
int trickyMove(u8* obj, f32* targetPos)
{
    f32 prospectivePos[3];
    f32 adjustedPos[3];
    u16 sfxIds[3];
    u16 sfxId;
    char* debugStrings;
    u8* state;
    f32 moveSpeed;
    f32 length;
    s16 previousYaw;
    int td;
    s16 turnDelta;
    int animId;
    u32 f;

    debugStrings = lbl_8031D2E8;
    state = ((GameObject*)obj)->extra;
    moveSpeed = ((TrickyState*)state)->speed;
    trickyDebugPrint(&sSkeetlaVelDebugFmt, moveSpeed);

    ((TrickyState*)state)->dirX = targetPos[0] - ((GameObject*)obj)->anim.worldPosX;
    ((TrickyState*)state)->dirZ = targetPos[2] - ((GameObject*)obj)->anim.worldPosZ;
    length =
        sqrtf((((TrickyState*)state)->dirX * ((TrickyState*)state)->dirX) +
            (((TrickyState*)state)->dirZ * ((TrickyState*)state)->dirZ));
    if (lbl_803E23DC != length)
    {
        ((TrickyState*)state)->dirX /= length;
        ((TrickyState*)state)->dirZ /= length;
    }

    if (moveSpeed < lbl_803E2420)
    {
        f32 stepX;
        f32 stepZ;
        stepX = lbl_803E2420 * ((TrickyState*)state)->dirX;
        prospectivePos[0] = stepX * timeDelta + ((GameObject*)obj)->anim.worldPosX;
        prospectivePos[1] = ((GameObject*)obj)->anim.worldPosY;
        stepZ = lbl_803E2420 * ((TrickyState*)state)->dirZ;
        prospectivePos[2] = stepZ * timeDelta + ((GameObject*)obj)->anim.worldPosZ;
    }
    else
    {
        prospectivePos[0] =
            timeDelta * (((TrickyState*)state)->dirX * moveSpeed) + ((GameObject*)obj)->anim.worldPosX;
        prospectivePos[1] = ((GameObject*)obj)->anim.worldPosY;
        prospectivePos[2] =
            timeDelta * (((TrickyState*)state)->dirZ * moveSpeed) + ((GameObject*)obj)->anim.worldPosZ;
    }

    adjustedPos[0] = prospectivePos[0];
    adjustedPos[1] = prospectivePos[1];
    adjustedPos[2] = prospectivePos[2];
    trickyApplyObjectAvoidanceToStep((f32*)(obj + 0x18), adjustedPos, targetPos);
    if (vec3f_distanceSquared(prospectivePos, adjustedPos) > lbl_803E2468)
    {
        ((TrickyState*)state)->dirX = adjustedPos[0] - ((GameObject*)obj)->anim.worldPosX;
        ((TrickyState*)state)->dirZ = adjustedPos[2] - ((GameObject*)obj)->anim.worldPosZ;
        length =
            sqrtf((((TrickyState*)state)->dirX * ((TrickyState*)state)->dirX) +
                (((TrickyState*)state)->dirZ * ((TrickyState*)state)->dirZ));
        if (lbl_803E23DC != length)
        {
            ((TrickyState*)state)->dirX /= length;
            ((TrickyState*)state)->dirZ /= length;
        }
    }

    if (!(moveSpeed >= lbl_803E2420))
    {
        skeetla_updateFacingFromMoveVector(obj, &turnDelta);
        if (skeetla_isInWater(state) != 0)
        {
            objAnimFn_8013a3f0((int)obj, 7, lbl_803E2468, 0x2000000);
            ((TrickyState*)state)->unk79C = lbl_803E2440;
            ((TrickyState*)state)->unk838 = lbl_803E23DC;
            trickyDebugPrint(debugStrings + 0x184);
            return 1;
        }

        if (((TrickyState*)state)->unk08 == 1)
        {
            if ((skeetla_pathSpeedDelta(obj) >= lbl_803E23DC
                     ? skeetla_pathSpeedDelta(obj)
                     : -skeetla_pathSpeedDelta(obj)) > lbl_803E23DC)
            {
                ((TrickyState*)state)->unk7A4 -= timeDelta;
                if (((TrickyState*)state)->unk7A4 <= lbl_803E23DC)
                {
                    ((TrickyState*)state)->unk7A4 = (f32)(int)
                    randomGetRange(600, 1200);
                    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)
                    {
                        if (moveSpeed > lbl_803E23E8)
                        {
                            sfxId = randomGetRange(0x34d, 0x34e);
                            skeetla_playFootstepSfx(obj, sfxId);
                        }
                        else
                        {
                            *(u32*)sfxIds = gSkeetlaFootstepSfxIds01;
                            sfxIds[2] = gSkeetlaFootstepSfxId2;
                            if (GameBit_Get(0x25) != 0)
                            {
                                randomGetRange(0, 2);
                            }
                            else
                            {
                                randomGetRange(0, 1);
                            }
                            sfxId = sfxIds[randomGetRange(0, 2)];
                            skeetla_playFootstepSfx(obj, sfxId);
                        }
                    }
                }
            }
        }

        if (moveSpeed > lbl_803E246C)
        {
            ((TrickyState*)state)->unk7A0f = lbl_803E2440;
            objAnimFn_8013a3f0((int)obj, 0x30, lbl_803E2468, 0x3000000);
        }
        else if (moveSpeed > lbl_803E23E8)
        {
            objAnimFn_8013a3f0((int)obj, 5, lbl_803E2468, 0x3000000);
        }
        else if (moveSpeed > lbl_803E2470)
        {
            objAnimFn_8013a3f0((int)obj, 4, lbl_803E2468, 0x3000000);
        }
        else if (moveSpeed > lbl_803E2474)
        {
            objAnimFn_8013a3f0((int)obj, 2, lbl_803E2468, 0x3000000);
        }
        else
        {
            objAnimFn_8013a3f0((int)obj, 1, lbl_803E2468, 0x3000000);
        }
        trickyDebugPrint(debugStrings + 0x1a0);
        return 1;
    }

    previousYaw = ((GameObject*)obj)->anim.rotX;
    turnDelta = 0;
    skeetla_updateFacingFromMoveVector(obj, &turnDelta);
    td = turnDelta;

    if ((((TrickyState*)state)->stateFlags & 0x100000) != 0)
    {
        if (skeetla_isInWater(state) != 0)
        {
            trickyDebugPrint(debugStrings + 0x1bc);
            objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
            ((TrickyState*)state)->unk79C = lbl_803E2440;
            ((TrickyState*)state)->unk838 = lbl_803E23DC;
        }
        else
        {
            u32 flags;
            trickyDebugPrint(debugStrings + 0x1d0);
            flags = ((TrickyState*)state)->stateFlags;
            if ((flags & 0x400000) != 0)
            {
                if ((td >= 0 ? td : -td) > 0x3555)
                {
                    animId = 0x27;
                }
                else if ((td >= 0 ? td : -td) > 0x2000)
                {
                    animId = 0xb;
                }
                else
                {
                    animId = 9;
                }
            }
            else if ((flags & 0x800000) != 0)
            {
                if ((td >= 0 ? td : -td) > 0x3555)
                {
                    animId = 0x28;
                }
                else if ((td >= 0 ? td : -td) > 0x2000)
                {
                    animId = 0xc;
                }
                else
                {
                    animId = 10;
                }
            }
            ((GameObject*)obj)->anim.rotX = previousYaw;
            objAnimFn_8013a3f0((int)obj, animId, lbl_803E2478, 0x1000100);
        }
    }

    ((TrickyState*)state)->speed = lbl_803E2420;
    f = ((TrickyState*)state)->stateFlags;
    if (((f & 0x100000) == 0) && ((f & 0x200000) == 0))
    {
        return 0;
    }
    return 1;
}

int objAnimFn_8013a3f0(int obj, int newState, f32 speed, u32 flags)
{
    int t = *(int*)&((GameObject*)obj)->extra;
    f32 fz;
    if (((TrickyState*)t)->moveId == newState)
    {
        if (((GameObject*)obj)->anim.currentMove == newState)
        {
            ((TrickyState*)t)->moveProgress = speed;
            ((TrickyState*)t)->stateFlags = ((TrickyState*)t)->stateFlags | flags;
        }
        return 1;
    }
    if ((flags & 0x4000000) != 0)
    {
        ((TrickyState*)t)->animTransitionTimer = lbl_803E247C;
    }
    ((TrickyState*)t)->moveId = newState;
    ((TrickyState*)t)->moveProgressTarget = speed;
    ((TrickyState*)t)->pendingStateFlags = flags;
    if ((flags & 0x20) == 0)
    {
        ((TrickyState*)t)->stateFlags = ((TrickyState*)t)->stateFlags & ~(u64)0x20;
    }
    if ((flags & 0x40) == 0)
    {
        ((TrickyState*)t)->stateFlags = ((TrickyState*)t)->stateFlags & ~(u64)0x40;
    }
    if ((flags & 0x80) == 0)
    {
        ((TrickyState*)t)->stateFlags = ((TrickyState*)t)->stateFlags & ~(u64)0x80;
    }
    if ((flags & 0x100) == 0)
    {
        ((TrickyState*)t)->stateFlags = ((TrickyState*)t)->stateFlags & ~(u64)0x100;
    }
    fz = lbl_803E23E8;
    ((TrickyState*)t)->sidestepDelta = fz;
    ((TrickyState*)t)->backstepDelta = fz;
    ((TrickyState*)t)->verticalDelta = fz;
    ((TrickyState*)t)->rotStepScale = fz;
    if (((TrickyState*)t)->animTransitionTimer >= lbl_803E247C)
    {
        return 1;
    }
    return 0;
}

#pragma scheduling on
#pragma peephole on
static void* skeetla_validateRouteEntry(void* entry)
{
    if (entry == NULL)
    {
        return NULL;
    }
    if (((((ObjfsaRomCurveDef*)entry)->requiredBit != -1) && (GameBit_Get(((ObjfsaRomCurveDef*)entry)->requiredBit) == 0)) ||
        ((((ObjfsaRomCurveDef*)entry)->forbiddenBit != -1) && (GameBit_Get(((ObjfsaRomCurveDef*)entry)->forbiddenBit) != 0)))
    {
        entry = NULL;
    }
    else
    {
        return entry;
    }

    return entry;
}

#pragma scheduling off
#pragma peephole off
void* trickyFindNearestLinkedRouteEntry(u8* context, u8* routeDef, int linkSelector, int routeFlagValue)
{
    void* candidates[4];
    void* entry;
    f32 bestDistance;
    f32 distance;
    u16 mask;
    u16 i;
    u16 count;
    u16 bestIndex;
    int curveId;
    s16 requiredBit;
    s16 forbiddenBit;

    i = 0;
    count = 0;
    mask = 1;
    while (i < 4)
    {
        curveId = ((ObjfsaRomCurveDef*)routeDef)->linkIds[i];
        if ((curveId > -1) && (((((ObjfsaRomCurveDef*)routeDef)->blockedLinkMask & mask) ^ routeFlagValue) == 0))
        {
            candidates[count] = (*gRomCurveInterface)->getById(curveId);
            entry = candidates[count];
            if (entry != NULL)
            {
                if ((linkSelector == 0) || (routeDef[count + 4] == linkSelector))
                {
                    requiredBit = ((ObjfsaRomCurveDef*)entry)->requiredBit;
                    if ((requiredBit == -1) || (GameBit_Get(requiredBit) != 0))
                    {
                        forbiddenBit = ((ObjfsaRomCurveDef*)entry)->forbiddenBit;
                        if ((forbiddenBit == -1) || (GameBit_Get(forbiddenBit) == 0))
                        {
                            if (((s8)routeDef[0x1a] != 9) || (*(s8*)((u8*)entry + 0x1a) != 8))
                            {
                                count++;
                            }
                        }
                    }
                }
            }
        }
        i++;
        mask <<= 1;
        routeFlagValue <<= 1;
    }

    if (count != 0)
    {
        bestDistance = getXZDistance((f32*)(((TrickyState*)context)->playerObj + 0x18), (f32*)((u8*)candidates[0] + 8));
        bestIndex = 0;
        for (i = 1; i < count; i++)
        {
            distance = getXZDistance((f32*)(((TrickyState*)context)->playerObj + 0x18), (f32*)((u8*)candidates[i] + 8));
            if (distance < bestDistance)
            {
                bestDistance = distance;
                bestIndex = i;
            }
        }

        return candidates[bestIndex];
    }
    return NULL;
}

#pragma dont_inline on
void* trickyFindPathRouteEntry(u8* state, u32 route, int pathId)
{
    void* entry;

    if (pathId == 0)
    {
        return NULL;
    }

    if ((((TrickyState*)state)->unk6EC == pathId) && (*(u32*)&((TrickyState*)state)->unk6E8 == route))
    {
        ((TrickyState*)state)->unk6E8 = fn_8004B118(state + 0x6b8);
        entry = ((TrickyState*)state)->unk6E8;
        if (entry == NULL)
        {
            return NULL;
        }

        if (entry == NULL)
        {
            entry = NULL;
        }
        else if (((((ObjfsaRomCurveDef*)entry)->requiredBit != -1) && (GameBit_Get(((ObjfsaRomCurveDef*)entry)->requiredBit) == 0)) ||
            ((((ObjfsaRomCurveDef*)entry)->forbiddenBit != -1) && (GameBit_Get(((ObjfsaRomCurveDef*)entry)->forbiddenBit) != 0)))
        {
            entry = NULL;
        }
        ((TrickyState*)state)->unk6E8 = entry;
        entry = ((TrickyState*)state)->unk6E8;
        if (entry != NULL)
        {
            return entry;
        }
    }

    fn_8004B31C(state + 0x6b8, route, *(int*)&((TrickyState*)state)->unk28, pathId,
                ((TrickyState*)state)->route.reverse);
    if (fn_8004B218(state + 0x6b8, 0x1f4) != 1)
    {
        return NULL;
    }

    fn_8004B148(state + 0x6b8);
    ((TrickyState*)state)->unk6E8 = fn_8004B118(state + 0x6b8);
    ((TrickyState*)state)->unk6EC = pathId;
    return ((TrickyState*)state)->unk6E8;
}
#pragma dont_inline reset

int trickyFindReachableRouteIndex(u8* state, u32* routes, u8* routeFlags, int pathId)
{
    s8 status[TRICKY_ROUTE_CANDIDATE_COUNT];
    s8 i;
    s8 pass;
    s8 failedCount;

    for (i = 0; i < TRICKY_ROUTE_CANDIDATE_COUNT; i++)
    {
        if (routes[i] != 0)
        {
            fn_8004B31C(state + 0x538 + i * 0x30, routes[i], *(int*)&((TrickyState*)state)->unk28, pathId, routeFlags[i]);
        }
    }

    for (pass = 0; pass < 100; pass++)
    {
        failedCount = 0;
        for (i = 0; i < TRICKY_ROUTE_CANDIDATE_COUNT; i++)
        {
            if (routes[i] != 0)
            {
                status[i] = fn_8004B218(state + 0x538 + i * 0x30, 1);
            }
            else
            {
                status[i] = -1;
            }

            switch (status[i])
            {
            case 1:
                return i;
            case -1:
                routes[i] = 0;
                failedCount++;
                break;
            }
        }

        switch (failedCount)
        {
        case 7:
            for (i = 0; i < TRICKY_ROUTE_CANDIDATE_COUNT; i++)
            {
                if (routes[i] != 0)
                {
                    status[i] = fn_8004B218(state + 0x538 + i * 0x30, 0x1f4);
                    if (status[i] == 1)
                    {
                        return i;
                    }
                    return -1;
                }
            }
        case 8:
            return -1;
        }
    }

    return -1;
}

#pragma peephole on
void* trickySelectRouteEntry(u8* state, u8* routeDef, u32 routeFlagValue)
{
    void* entry;

    entry = NULL;

    if ((*(u8**)&((TrickyState*)state)->unk528 == routeDef) &&
        (((TrickyState*)state)->unk530 == ((TrickyState*)state)->unk532) &&
        (((TrickyState*)state)->unk536 == (routeFlagValue & 0xff)))
    {
        entry = skeetla_validateRouteEntry(((TrickyState*)state)->unk52C);
    }

    if (entry == NULL)
    {
        entry = trickyFindNearestLinkedRouteEntry(state, routeDef, ((TrickyState*)state)->unk532,
                                                  routeFlagValue & 0xff);
        if (entry == NULL)
        {
            entry = trickyFindPathRouteEntry(state, (u32)routeDef, ((TrickyState*)state)->unk532);
        }

        if (entry == NULL)
        {
            if (((TrickyState*)state)->unk534 != 0)
            {
                entry = trickyFindNearestLinkedRouteEntry(state, routeDef, ((TrickyState*)state)->unk534,
                                                          routeFlagValue & 0xff);
                if (entry == NULL)
                {
                    entry = trickyFindPathRouteEntry(state, (u32)routeDef, ((TrickyState*)state)->unk534);
                }
                if (entry != NULL)
                {
                    ((TrickyState*)state)->unk532 = ((TrickyState*)state)->unk534;
                }
            }

            if (entry == NULL)
            {
                entry = trickyFindNearestLinkedRouteEntry(state, routeDef, 0, routeFlagValue & 0xff);
                ((TrickyState*)state)->unk532 = 0;
            }
        }
    }

    *(u8**)&((TrickyState*)state)->unk528 = routeDef;
    ((TrickyState*)state)->unk52C = entry;
    ((TrickyState*)state)->unk530 = ((TrickyState*)state)->unk532;
    ((TrickyState*)state)->unk536 = routeFlagValue;
    return entry;
}

#pragma peephole off
void trickyRankLinkedRouteCandidates(u8* obj, u8* outRouteFlags, s16 linkSelector, void** outRoutes)
{
    f32 bestDistances[TRICKY_ROUTE_CANDIDATE_COUNT];
    int i;
    void** curves;
    void* curve;
    u8 j;
    void* linkedCurve;
    u8 routeFlags;
    f32 cz;
    f32* p;
    f32 score;
    f32 init;
    int count;
    u8 k;
    int linkCurveId;
    u8* state;

    state = ((GameObject*)obj)->extra;
    curves = (void**)(*gRomCurveInterface)->getCurves(&count);

    init = lbl_803E2418;
    for (i = 0; i < TRICKY_ROUTE_CANDIDATE_COUNT; i++)
    {
        bestDistances[i] = init;
        outRoutes[i] = NULL;
    }

    if (linkSelector == 0)
    {
        return;
    }

    for (i = 0; i < count; i++)
    {
        curve = curves[i];
        if ((((ObjfsaRomCurveDef*)curve)->type != 0x24) || (*(u8*)((u8*)curve + 3) != 0))
        {
            continue;
        }
        if (((((ObjfsaRomCurveDef*)curve)->requiredBit != -1) &&
                (GameBit_Get(((ObjfsaRomCurveDef*)curve)->requiredBit) == 0)) ||
            ((((ObjfsaRomCurveDef*)curve)->forbiddenBit != -1) &&
                (GameBit_Get(((ObjfsaRomCurveDef*)curve)->forbiddenBit) != 0)))
        {
            continue;
        }

        cz = ((ObjfsaRomCurveDef*)curve)->z;
        p = *(f32**)&((TrickyState*)state)->unk28;
        {
            f32 sq0 = (p[2] - cz) * (p[2] - cz);
            f32 sq1 = (p[0] - ((ObjfsaRomCurveDef*)curve)->x) * (p[0] - ((ObjfsaRomCurveDef*)curve)->x);
            f32 sq2 = (((GameObject*)obj)->anim.worldPosX - ((ObjfsaRomCurveDef*)curve)->x) * (((GameObject*)obj)->anim.worldPosX - ((ObjfsaRomCurveDef*)curve)->x);
            f32 sq3 = (((GameObject*)obj)->anim.worldPosZ - cz) * (((GameObject*)obj)->anim.worldPosZ - cz);
            score = sq0 + (sq1 + (sq2 + sq3));
        }
        if (score < bestDistances[7])
        {
            for (j = 0; j < 4; j++)
            {
                linkCurveId = ((ObjfsaRomCurveDef*)curve)->linkIds[j];
                if ((linkCurveId > -1) && (*(u8*)((u8*)curve + 4 + j) == linkSelector))
                {
                    if (*(s8*)((u8*)curve + 0x1a) == 8)
                    {
                        linkedCurve = (*gRomCurveInterface)->getById(linkCurveId);
                        if ((linkedCurve != NULL) && (*(s8*)((u8*)linkedCurve + 0x1a) == 9))
                        {
                            continue;
                        }
                    }

                    routeFlags = (u8)(((ObjfsaRomCurveDef*)curve)->blockedLinkMask >> (u8)j);
                    break;
                }
            }

            if (j == 4)
            {
                continue;
            }

            for (j = 0; j < TRICKY_ROUTE_CANDIDATE_COUNT; j++)
            {
                if (score < bestDistances[j])
                {
                    for (k = 7; k > j; k--)
                    {
                        outRouteFlags[k] = outRouteFlags[k - 1];
                        outRoutes[k] = outRoutes[k - 1];
                        bestDistances[k] = bestDistances[k - 1];
                    }

                    outRouteFlags[j] = (routeFlags & 1) ^ 1;
                    outRoutes[j] = curve;
                    bestDistances[j] = score;
                    break;
                }
            }
        }
    }
}

typedef struct SkeetlaParticleSpawnArgs
{
    s16 objectId;
    s16 pad0;
    u16 sourceId;
    u16 pad1;
    u32 pad2;
    f32 x;
    f32 y;
    f32 z;
} SkeetlaParticleSpawnArgs;

#define SKEETLA_LINKED_SOURCE_ID_OBJ_A 0x1ca
#define SKEETLA_LINKED_SOURCE_ID_OBJ_B 0x160
#define SKEETLA_PARTICLE_SPARK_A 0xca
#define SKEETLA_PARTICLE_SPARK_B 0xcb
#define SKEETLA_PARTICLE_SPAWN_FLAGS 0x200001
#define SKEETLA_PARTICLE_RANDOM_RATE 4

void skeetla_spawnLinkedSparks(u8* obj)
{
    u8* state;
    u8* linkedObj;
    SkeetlaParticleSpawnArgs args;

    state = ((GameObject*)obj)->extra;
    linkedObj = *(u8**)&((TrickyState*)state)->followObj;

    args.x = ((TrickyState*)state)->sparkPos0X;
    args.y = ((TrickyState*)state)->sparkPos0Y;
    args.z = ((TrickyState*)state)->sparkPos0Z;
    args.objectId = ((GameObject*)obj)->anim.rotX;
    if (((GameObject*)linkedObj)->anim.seqId == SKEETLA_LINKED_SOURCE_ID_OBJ_A)
    {
        args.sourceId =
            (u8)(*(u32 (**)(u8*))(*(int*)(*(int*)&((GameObject*)linkedObj)->anim.dll) + 0x28))(linkedObj);
    }
    else if (((GameObject*)linkedObj)->anim.seqId == SKEETLA_LINKED_SOURCE_ID_OBJ_B)
    {
        args.sourceId =
            (u8)(*(u32 (**)(u8*))(*(int*)(*(int*)&((GameObject*)linkedObj)->anim.dll) + 0x28))(linkedObj);
    }
    else
    {
        args.sourceId = 0;
    }

    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0)
    {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_A, &args,
                                         SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0)
    {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_B, &args,
                                         SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }

    args.x = ((TrickyState*)state)->sparkPos1X;
    args.y = ((TrickyState*)state)->sparkPos1Y;
    args.z = ((TrickyState*)state)->sparkPos1Z;
    args.objectId = ((GameObject*)obj)->anim.rotX;

    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0)
    {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_A, &args,
                                         SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0)
    {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_B, &args,
                                         SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }
}

#pragma peephole on
void trickyAdjustStepAroundPoint(f32* start, f32* end, f32* guardPoint, f32* center, f32 minDistance, f32 moveDistance)
{
    f32 projection[3];
    f32 dx;
    f32 centerToEnd;
    f32 minDistanceSq;
    f32 limitDistanceSq;
    f32 guardDistance;
    f32 startGuardDistance;
    f32 slope;
    f32 intercept;
    f32 perpSlope;
    f32 dz;
    f32 centerToStart;
    f32 length;
    int useBlendedDistance;

    useBlendedDistance = 0;
    centerToStart = getXZDistance(center, start);
    centerToEnd = getXZDistance(center, end);
    minDistanceSq = minDistance * minDistance;
    limitDistanceSq = moveDistance * moveDistance;

    if (centerToEnd > centerToStart)
    {
        return;
    }

    guardDistance = getXZDistance(guardPoint, center);
    if (guardDistance < minDistanceSq)
    {
        return;
    }

    startGuardDistance = getXZDistance(start, guardPoint);
    if (getXZDistance(start, center) > startGuardDistance)
    {
        return;
    }

    if (centerToStart < limitDistanceSq)
    {
        limitDistanceSq = centerToStart;
        useBlendedDistance = 1;
    }

    if (!(centerToEnd < limitDistanceSq))
    {
        return;
    }

    slope = (end[2] - start[2]) / (end[0] - start[0]);
    intercept = start[2] - (slope * start[0]);
    perpSlope = (start[0] - end[0]) / (end[2] - start[2]);
    projection[0] = ((center[2] - (perpSlope * center[0])) - intercept) / (slope - perpSlope);
    projection[2] = (slope * projection[0]) + intercept;

    if (!(getXZDistance(center, projection) < minDistanceSq))
    {
        return;
    }

    dx = end[0] - center[0];
    dz = end[2] - center[2];
    length = sqrtf((dx * dx) + (dz * dz));
    if (lbl_803E23DC != length)
    {
        dx /= length;
        dz /= length;
    }

    if (useBlendedDistance != 0)
    {
        moveDistance = sqrtf(limitDistanceSq);
        moveDistance =
            moveDistance - ((moveDistance - sqrtf(centerToEnd)) * lbl_803E2480);
    }

    end[0] = center[0] + (dx * moveDistance);
    end[2] = center[2] + (dz * moveDistance);
}

#pragma peephole off
void trickyApplyObjectAvoidanceToStep(f32* start, f32* end, f32* guardPoint)
{
    int count;
    int startIndex;
    int objectCount;
    int i;
    void** objects;
    u8* obj;
    u8* def;
    ObjHitsPriorityState* hitState;
    u16 minRadius;

    objects = ObjGroup_GetObjects(0x40, &count);
    for (i = 0; i < count; i++)
    {
        obj = objects[i];
        def = *(u8**)&((GameObject*)obj)->anim.placementData;
        trickyAdjustStepAroundPoint(start, end, guardPoint, &((GameObject*)obj)->anim.worldPosX,
                                    lbl_803E2484 * (f32)(u32) * (u16*)(def + 0x18),
                                    lbl_803E2484 * (f32)(u32) * (u16*)(def + 0x1a));
    }

    objects = ObjList_GetObjects(&startIndex, &objectCount);
    for (i = startIndex; i < objectCount; i++)
    {
        obj = objects[i];
        def = *(u8**)&((GameObject*)obj)->anim.modelInstance;
        minRadius = *(u16*)(def + 0x84);
        if (minRadius != 0)
        {
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if ((hitState != NULL) && ((*(s16*)&hitState->flags & 1) != 0))
            {
                trickyAdjustStepAroundPoint(start, end, guardPoint, &((GameObject*)obj)->anim.worldPosX,
                                            lbl_803E2484 * (f32)(u32)minRadius,
                                            *(f32*)&lbl_803E2484 * (f32)(u32) * (u16*)(def + 0x86));
            }
        }
    }
}
#pragma peephole reset
