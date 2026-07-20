/*
 * skeetla - Tricky (the companion dinosaur) per-frame collision, ground
 * snapping and path-control update.
 *
 * trickyUpdateCollisionAndPathState snaps Tricky to the ground, applies water
 * buoyancy, processes priority hits (lighting fx, hit sparks, out-of-water
 * bark), then drives the path-control interface and copies the resulting
 * yaw/roll back onto the object. trickyAdvanceRouteTargetAhead walks the
 * RomCurve route target forward and trickyTurnTowardYaw eases the object's
 * facing toward a requested yaw.
 */
#include "main/dll/partfx_interface.h"
#include "main/track_dolphin_api.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/objfsa_romcurve.h"
#include "main/vecmath.h"
#include "main/lightmap_api.h"
#include "main/pi_dolphin_api.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/obj_list.h"
#include "main/obj_group.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objhits.h"
#include "main/objHitReact.h"
#include "main/objfx.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/dll/objfsa.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/dll/skeetla.h"
#include "main/objprint_sound_api.h"
#include "main/dll/dll_00C4_tricky_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"


/* group owned by another DLL, queried here */
#define SIDEREPEL_OBJGROUP      0x40 /* DLL 0xEB siderepel */
#define SKEETLA_TARGET_OBJGROUP 5

/* Per-node fan-out limit: status[]/bestDistances[]/outRoutes[] hold at most
 * this many linked route candidates (status[8] / f32 bestDistances[8]). */
#define TRICKY_ROUTE_CANDIDATE_COUNT 8

#define SKEETLA_LINKED_SOURCE_ID_OBJ_A 0x1ca
#define SKEETLA_LINKED_SOURCE_ID_OBJ_B 0x160
#define SKEETLA_PARTICLE_SPARK_A       0xca
#define SKEETLA_PARTICLE_SPARK_B       0xcb

/* attacker seqId that triggers the staff-impact sfx (retail OBJECTS.bin). */
#define SKEETLA_ATTACKER_SEQID_STAFF 0x69 /* "staff" (DLL 0xE2) */
#define SKEETLA_PARTICLE_SPAWN_FLAGS   0x200001
#define SKEETLA_PARTICLE_RANDOM_RATE   4

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
extern f32 lbl_803E244C;
extern f32 lbl_803E2448;
extern f32 lbl_803E23F8;
extern f32 lbl_803E2450;
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
extern char lbl_8031D2E8[];
extern u32 gSkeetlaFootstepSfxIds01;

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
        state->heightUpdateActive = 0;
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.previousLocalPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.previousLocalPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
    }

    state->stateFlags &= ~0x80000LL;

    if (state->groundSnapCounter != 0)
    {
        state->groundSnapCounter -= 1;
        doGroundSnap = 1;
    }
    else if ((state->stateFlags & 0x2000) != 0)
    {
        doGroundSnap = 1;
    }

    if (doGroundSnap != 0)
    {
        hitDetectFn_800658a4((GameObject*)obj, ((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                             ((GameObject*)obj)->anim.worldPosZ, &hitOffsetY, 0);
        ((GameObject*)obj)->anim.localPosY -= hitOffsetY;
        state->heightUpdateActive = 0;
    }

    if (((s8)state->heightUpdateActive != 0) && (((state->statusFlags >> 5) & 1) == 0u))
    {
        if (lbl_803E23DC == state->waterLevel)
        {
            doHeightSnap = 0;
        }
        else if (lbl_803E2410 == state->eventTime)
        {
            doHeightSnap = 1;
        }
        else if (state->currentTime - state->eventTime > lbl_803E2414)
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
            ((GameObject*)obj)->anim.localPosY = state->currentTime - lbl_803E23EC;
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
    if ((((GameObject*)obj)->anim.hitReactState->flags & OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED) == 0 ||
        (((GameObject*)lastContactObj)->anim.seqId == 0x1f))
    {
        lastContactObj = NULL;
    }

    if ((state->stateFlags & 8) != 0)
    {
        state->contactTimer += timeDelta;
        if (state->contactTimer >= lbl_803E242C)
        {
            if (vec3f_distanceSquared((f32*)(obj + 0x18), &Obj_GetPlayerObject()->anim.worldPosX) > lbl_803E2430)
            {
                state->contactTimer -= lbl_803E242C;
                ((GameObject*)obj)->anim.modelInstance->runtimeSourceHitMask = 0x7f;
                state->stateFlags &= ~8LL;
            }
        }
    }
    else if ((state->lastContactObj != NULL) && (lastContactObj == state->lastContactObj))
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
    hitKind = ObjHits_PollPriorityHitWithCooldown((GameObject*)obj, &state->hitCooldown, (int*)&lastContactObj,
                                                  (hitPosPtr = hitPos));
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
        if (((GameObject*)lastContactObj)->anim.seqId == SKEETLA_ATTACKER_SEQID_STAFF)
        {
        Sfx_PlayFromObject((u32)obj, SFXTRIG_stftest_var);
        }
        break;
    case 0x1f:
        state->particleTimer = lbl_803E2438;
        break;
    }

    if ((s8)state->heightUpdateActive == 0)
    {
        (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
    }

    if ((coordsToMapCell(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ) == 0xe) ||
        ((u32)ObjGroup_FindNearestObject(SKEETLA_TARGET_OBJGROUP, (GameObject*)obj, &nearestDistance) != 0u))
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

int trickyAdvanceRouteTargetAhead(int obj, RomCurveWalker* route, f32 speed)
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

int trickyTurnTowardYaw(u8* obj, s16 targetYaw)
{
    u8* state;
    int currentYaw;
    int delta;
    int step;

    state = ((GameObject*)obj)->extra;
    ((TrickyState*)state)->targetYaw = targetYaw;

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
