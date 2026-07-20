/*
 * curvefish (DLL 0x0103) - a fish that swims an endless loop along a ROM
 * curve path (Curve_AdvanceAlongPath), fading in on spawn and steering its
 * yaw toward the next path node each frame.
 *
 * CurveFish_update is a four-stage state machine (CurveFishState.mode):
 *   0  wait placement->waitFrames game-frames, then advance;
 *   1  teleport to placement->base.pos{X,Y,Z}, bind the walker to the three curve
 *      nodes nearest that point, seed speed; bail back to wait if the curve
 *      bind fails;
 *   2  fade alpha in over one frame-time, then go to stage 3;
 *   3  cruise: speed is bumped up on a priority hit, accelerated toward the
 *      player when in range (placement->playerRadius), else random-walked; the
 *      swim/glide animation move is chosen from the speed band and the body
 *      is stepped along the path with yaw turning capped at 0x180/frame.
 *      Reaching the route end (curveFn_800da23c) resets to stage 0.
 *
 * Its descriptor follows the implementation below.
 */
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/dll_0103_curvefish.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/frame_timing.h"

typedef enum CurveFishMode
{
    CURVEFISH_MODE_WAIT = 0,    /* wait placement->waitFrames game-frames */
    CURVEFISH_MODE_SPAWN = 1,   /* teleport to spawn point and bind the curve walker */
    CURVEFISH_MODE_FADE_IN = 2, /* fade alpha in over one frame-time */
    CURVEFISH_MODE_CRUISE = 3,  /* cruise along the path; reaching the end resets to wait */
} CurveFishMode;

/* per-frame cap on the body's yaw turn toward the next path node */
#define CURVEFISH_MAX_YAW_TURN 0x180

/* ROM curve query key for the fish path curves */
union CurveFishConstU32 { u32 u; };
const union CurveFishConstU32 gCurveFishCurveQueryKey = { ROMCURVE_TYPE_CURVEFISH };

int CurveFish_getExtraSize(void)
{
    return 0x120;
}

void CurveFish_update(int obj)
{
    CurveFishState* state;
    CurveFishPlacement* placement;
    void* player;
    CurveFishPlacement* placementReloaded;
    u32 curveQuery;
    int firstNode;
    int secondNode;
    int thirdNode;
    int nextNode;
    f32 maxHitSpeed;
    f32 speedThreshold;
    f32 distance;
    int i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 mag;
    f32 distLimit;
    f32 speedDelta;
    int targetYaw;
    int yawDelta;

    state = ((GameObject*)obj)->extra;
    placement = *(CurveFishPlacement**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    placementReloaded = *(CurveFishPlacement**)&((GameObject*)obj)->anim.placementData;
    curveQuery = gCurveFishCurveQueryKey.u;

    state->phaseTimer += timeDelta;

    switch (state->mode)
    {
    case CURVEFISH_MODE_WAIT:
    {
        f32 waitTime = 60.0f * (f32)(u32)placement->waitFrames;
        if (!(state->phaseTimer >= waitTime))
        {
            return;
        }
        state->phaseTimer -= waitTime;
        state->mode = CURVEFISH_MODE_SPAWN;
    }
    case CURVEFISH_MODE_SPAWN:
        ((GameObject*)obj)->anim.localPosX = placementReloaded->base.posX;
        ((GameObject*)obj)->anim.localPosY = placementReloaded->base.posY;
        ((GameObject*)obj)->anim.localPosZ = placementReloaded->base.posZ;

        firstNode = (int)(*gRomCurveInterface)
                        ->getById((*gRomCurveInterface)->find(
                            ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                            ((GameObject*)obj)->anim.localPosZ, (int*)&curveQuery, 1, -1));
        secondNode =
            (int)(*gRomCurveInterface)->getById(
                (*gRomCurveInterface)->getRandomUnblockedLink((RomCurveDef*)firstNode, 0));
        thirdNode =
            (int)(*gRomCurveInterface)->getById(
                (*gRomCurveInterface)->getRandomUnblockedLink((RomCurveDef*)secondNode, 0));

        if (RomCurve_setupHermiteSegment((RomCurveWalker*)state, (void*)firstNode, (void*)secondNode, (void*)thirdNode) != 0)
        {
            return;
        }
        state->mode = CURVEFISH_MODE_FADE_IN;
        state->speed = 0.0f;
    case CURVEFISH_MODE_FADE_IN:
        if (state->phaseTimer <= 60.0f)
        {
            ((GameObject*)obj)->anim.alpha = (u8)(int)(255.0f * (state->phaseTimer / 60.0f));
            return;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        state->mode = CURVEFISH_MODE_CRUISE;
    case CURVEFISH_MODE_CRUISE:
        if (ObjHits_GetPriorityHit((GameObject*)(obj), 0, 0, 0) != 0)
        {
            state->speed = 2.0f * state->maxSpeed;
        }
        else if (playerGetFlags3F0Bit5((GameObject*)player) != 0 &&
                 getXZDistance(&((GameObject*)player)->anim.localPosX, (f32*)(obj + 0xc)) <
                     (f32)(u32)placement->playerRadius * (f32)(u32)placement->playerRadius)
        {
            speedDelta = 2.0f * (f32)(u32)placementReloaded->speedChange;
            state->speed += (speedDelta * timeDelta) / 1000.0f;
            if (state->speed > (maxHitSpeed = 2.0f * state->maxSpeed))
            {
                state->speed = maxHitSpeed;
            }
        }
        else
        {
            speedDelta = (f32)(int)randomGetRange(-placementReloaded->speedChange,
                                                  placementReloaded->speedChange << 1);
            state->speed += (speedDelta * timeDelta) / 1000.0f;
            if (state->speed < 0.0f)
            {
                state->speed = 0.0f;
            }
            else if (state->speed > state->maxSpeed)
            {
                state->speed = state->maxSpeed;
            }
        }

        speedThreshold = state->maxSpeed / 4.0f;
        if (state->speed < speedThreshold)
        {
            if (((GameObject*)obj)->anim.currentMove == 0 && state->animTimer > 120.0f)
            {
                ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
                state->animTimer = 0.0f;
            }
            state->moveStepScale = 0.0075f;
        }
        else if (state->speed > 3.0f * state->maxSpeed / 4.0f)
        {
            if (((GameObject*)obj)->anim.currentMove == 0 && state->animTimer > 240.0f)
            {
                ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
                state->animTimer = 0.0f;
            }
            state->moveStepScale = 0.015f;
        }
        else
        {
            if (((GameObject*)obj)->anim.currentMove == 1 && state->animTimer > 240.0f)
            {
                ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
                state->animTimer = 0.0f;
            }
            state->moveStepScale = (0.015f * state->speed) / state->maxSpeed;
        }

        if (0.0f != state->speed)
        {
            distLimit = state->speed * timeDelta;
            distLimit *= distLimit;
            distance = getXZDistance(&state->targetX, (f32*)(obj + 0xc));
            i = 0;
            while (distLimit > distance && i < 5)
            {
                Curve_AdvanceAlongPath(&state->route.curve, 2.0f);
                distance = getXZDistance(&state->targetX, (f32*)(obj + 0xc));
                i++;
            }

            if (state->hasRouteEdge != 0)
            {
                nextNode = (*gRomCurveInterface)->getRandomUnblockedLink((RomCurveDef*)state->routeCursor, 0);
                if (curveFn_800da23c(&state->route, (*gRomCurveInterface)->getById(nextNode)) != 0)
                {
                    state->mode = CURVEFISH_MODE_WAIT;
                    state->phaseTimer = 0.0f;
                    ((GameObject*)obj)->anim.alpha = 0;
                    return;
                }
            }

            dx = state->targetX - ((GameObject*)obj)->anim.localPosX;
            dy = (state->targetY + (f32)(u32)placement->targetYOffset) - ((GameObject*)obj)->anim.localPosY;
            dz = state->targetZ - ((GameObject*)obj)->anim.localPosZ;
            mag = sqrtf(dx * dx + dy * dy + dz * dz);
            dx /= mag;
            dy /= mag;
            dz /= mag;

            ((GameObject*)obj)->anim.localPosX += dx * state->speed;
            ((GameObject*)obj)->anim.localPosY += dy * state->speed;
            ((GameObject*)obj)->anim.localPosZ += dz * state->speed;

            targetYaw = (s16)getAngle(dx, dz);
            yawDelta = targetYaw - ((u16)(((GameObject*)obj)->anim.rotX));
            if (yawDelta > 0x8000)
            {
                yawDelta -= 0xffff;
            }
            if (yawDelta < -0x8000)
            {
                yawDelta += 0xffff;
            }
            if (yawDelta > CURVEFISH_MAX_YAW_TURN)
            {
                ((GameObject*)obj)->anim.rotX += CURVEFISH_MAX_YAW_TURN;
            }
            else if (yawDelta < -CURVEFISH_MAX_YAW_TURN)
            {
                ((GameObject*)obj)->anim.rotX -= CURVEFISH_MAX_YAW_TURN;
            }
            else
            {
                ((GameObject*)obj)->anim.rotX = targetYaw;
            }
        }

        ObjAnim_AdvanceCurrentMove((int)obj, state->moveStepScale, timeDelta, NULL);
        state->animTimer += timeDelta;
    default:
        return;
    }
}

void CurveFish_init(GameObject* obj, CurveFishPlacement* placement)
{
    CurveFishState* state;
    u32 flags;
    state = obj->extra;
    flags = obj->objectFlags;
    flags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->objectFlags = flags;
    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase *
                                ((f32)(u32)placement->rootMotionScalePercent / 100.0f);
    state->mode = CURVEFISH_MODE_SPAWN;
    state->maxSpeed = (f32)(u32)placement->speedChange / 100.0f;
}


ObjectDescriptor gCurveFishObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)CurveFish_init,
    (ObjectDescriptorCallback)CurveFish_update,
    0,
    0,
    0,
    0,
    CurveFish_getExtraSize,
};
