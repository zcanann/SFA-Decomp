/*
 * DLL 0x103 - CurveFish.
 *
 * Swims a ROM-curve network, fading in after each spawn and varying its
 * speed and animation in response to the player and priority hits.
 */
#include "dlls/objects/259_CurveFish.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/dll/player_api.h"
#include "main/objhits.h"

typedef enum CurveFishMode {
    CURVEFISH_MODE_WAIT = 0,
    CURVEFISH_MODE_SPAWN = 1,
    CURVEFISH_MODE_FADE_IN = 2,
    CURVEFISH_MODE_CRUISE = 3,
} CurveFishMode;

#define CURVEFISH_QUERY_TYPE_COUNT 1
#define CURVEFISH_QUERY_ACTION_ANY -1

#define CURVEFISH_FRAMES_PER_SECOND 60.0f
#define CURVEFISH_FADE_DURATION     60.0f
#define CURVEFISH_ALPHA_MAX_F       255.0f
#define CURVEFISH_ALPHA_MAX         0xFF

#define CURVEFISH_HIT_SPEED_MULTIPLIER 2.0f
#define CURVEFISH_SPEED_SCALE          1000.0f
#define CURVEFISH_SPEED_BAND_DIVISOR   4.0f
#define CURVEFISH_FAST_BAND_MULTIPLIER 3.0f
#define CURVEFISH_SPEED_PERCENT_SCALE  100.0f

#define CURVEFISH_MOVE_GLIDE             0
#define CURVEFISH_MOVE_SWIM              1
#define CURVEFISH_MOVE_EVENT_STEP_FRAMES 0x3C
#define CURVEFISH_SLOW_MOVE_DELAY        120.0f
#define CURVEFISH_FAST_MOVE_DELAY        240.0f
#define CURVEFISH_SLOW_ANIM_STEP         0.0075f
#define CURVEFISH_FAST_ANIM_STEP         0.015f

#define CURVEFISH_PATH_ADVANCE_STEP  2.0f
#define CURVEFISH_PATH_ADVANCE_LIMIT 5

#define CURVEFISH_MAX_YAW_TURN  0x180
#define CURVEFISH_YAW_HALF_TURN 0x8000
#define CURVEFISH_YAW_WRAP      0xFFFF

const CurveFishCurveQueryKey gCurveFishCurveQueryKey = { ROMCURVE_TYPE_CURVEFISH };

int CurveFish_getExtraSize(void) {
    return sizeof(CurveFishState);
}

void CurveFish_update(GameObject* obj) {
    CurveFishState* state;
    CurveFishPlacement* placement;
    GameObject* player;
    CurveFishPlacement* placementReloaded;
    int curveQuery;
    RomCurveDef* firstNode;
    RomCurveDef* secondNode;
    RomCurveDef* thirdNode;
    int nextNode;
    f32 boostedMaxSpeed;
    f32 slowSpeedThreshold;
    f32 distanceSq;
    int pathAdvanceCount;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 directionMagnitude;
    f32 travelDistanceSq;
    f32 speedDelta;
    int targetYaw;
    int yawDelta;

    state = obj->extra;
    placement = (CurveFishPlacement*)obj->anim.placementData;
    player = Obj_GetPlayerObject();
    placementReloaded = (CurveFishPlacement*)obj->anim.placementData;
    curveQuery = gCurveFishCurveQueryKey.type;

    state->modeTimer += timeDelta;

    switch (state->mode) {
    case CURVEFISH_MODE_WAIT: {
        f32 waitTime = CURVEFISH_FRAMES_PER_SECOND * (f32)(u32)placement->waitSeconds;
        if (!(state->modeTimer >= waitTime)) {
            return;
        }
        state->modeTimer -= waitTime;
        state->mode = CURVEFISH_MODE_SPAWN;
    }
        /* Fall through. */
    case CURVEFISH_MODE_SPAWN:
        obj->anim.localPosX = placementReloaded->base.posX;
        obj->anim.localPosY = placementReloaded->base.posY;
        obj->anim.localPosZ = placementReloaded->base.posZ;

        firstNode = (*gRomCurveInterface)
                        ->getById((*gRomCurveInterface)
                                      ->find(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &curveQuery,
                                             CURVEFISH_QUERY_TYPE_COUNT, CURVEFISH_QUERY_ACTION_ANY));
        secondNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomForwardLink(firstNode, 0));
        thirdNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomForwardLink(secondNode, 0));

        if (RomCurve_setupHermiteSegment(&state->route, firstNode, secondNode, thirdNode) != 0) {
            return;
        }
        state->mode = CURVEFISH_MODE_FADE_IN;
        state->speed = 0.0f;
        /* Fall through. */
    case CURVEFISH_MODE_FADE_IN:
        if (state->modeTimer <= CURVEFISH_FADE_DURATION) {
            obj->anim.alpha = (u8)(int)(CURVEFISH_ALPHA_MAX_F * (state->modeTimer / CURVEFISH_FADE_DURATION));
            return;
        }
        obj->anim.alpha = CURVEFISH_ALPHA_MAX;
        state->mode = CURVEFISH_MODE_CRUISE;
        /* Fall through. */
    case CURVEFISH_MODE_CRUISE:
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
            state->speed = CURVEFISH_HIT_SPEED_MULTIPLIER * state->maxSpeed;
        } else if (playerGetFlags3F0Bit5(player) != 0 &&
                   getXZDistanceSquared(&player->anim.localPosX, &obj->anim.localPosX) <
                       (f32)(u32)placement->playerRadius * (f32)(u32)placement->playerRadius) {
            speedDelta = CURVEFISH_HIT_SPEED_MULTIPLIER * (f32)(u32)placementReloaded->speedChange;
            state->speed += (speedDelta * timeDelta) / CURVEFISH_SPEED_SCALE;
            if (state->speed > (boostedMaxSpeed = CURVEFISH_HIT_SPEED_MULTIPLIER * state->maxSpeed)) {
                state->speed = boostedMaxSpeed;
            }
        } else {
            speedDelta = (f32)randomGetRange(-placementReloaded->speedChange, placementReloaded->speedChange << 1);
            state->speed += (speedDelta * timeDelta) / CURVEFISH_SPEED_SCALE;
            if (state->speed < 0.0f) {
                state->speed = 0.0f;
            } else if (state->speed > state->maxSpeed) {
                state->speed = state->maxSpeed;
            }
        }

        slowSpeedThreshold = state->maxSpeed / CURVEFISH_SPEED_BAND_DIVISOR;
        if (state->speed < slowSpeedThreshold) {
            if (obj->anim.currentMove == CURVEFISH_MOVE_GLIDE && state->moveTimer > CURVEFISH_SLOW_MOVE_DELAY) {
                ObjAnim_SetCurrentMove(obj, CURVEFISH_MOVE_SWIM, 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, CURVEFISH_MOVE_EVENT_STEP_FRAMES);
                state->moveTimer = 0.0f;
            }
            state->animStep = CURVEFISH_SLOW_ANIM_STEP;
        } else if (state->speed > CURVEFISH_FAST_BAND_MULTIPLIER * state->maxSpeed / CURVEFISH_SPEED_BAND_DIVISOR) {
            if (obj->anim.currentMove == CURVEFISH_MOVE_GLIDE && state->moveTimer > CURVEFISH_FAST_MOVE_DELAY) {
                ObjAnim_SetCurrentMove(obj, CURVEFISH_MOVE_SWIM, 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, CURVEFISH_MOVE_EVENT_STEP_FRAMES);
                state->moveTimer = 0.0f;
            }
            state->animStep = CURVEFISH_FAST_ANIM_STEP;
        } else {
            if (obj->anim.currentMove == CURVEFISH_MOVE_SWIM && state->moveTimer > CURVEFISH_FAST_MOVE_DELAY) {
                ObjAnim_SetCurrentMove(obj, CURVEFISH_MOVE_GLIDE, 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, CURVEFISH_MOVE_EVENT_STEP_FRAMES);
                state->moveTimer = 0.0f;
            }
            state->animStep = (CURVEFISH_FAST_ANIM_STEP * state->speed) / state->maxSpeed;
        }

        if (state->speed != 0.0f) {
            travelDistanceSq = state->speed * timeDelta;
            travelDistanceSq *= travelDistanceSq;
            distanceSq = getXZDistanceSquared(&state->route.posX, &obj->anim.localPosX);
            pathAdvanceCount = 0;
            while (travelDistanceSq > distanceSq && pathAdvanceCount < CURVEFISH_PATH_ADVANCE_LIMIT) {
                Curve_AdvanceAlongPath(&state->route.curve, CURVEFISH_PATH_ADVANCE_STEP);
                distanceSq = getXZDistanceSquared(&state->route.posX, &obj->anim.localPosX);
                pathAdvanceCount++;
            }

            if (state->route.atSegmentEnd != 0) {
                nextNode = (*gRomCurveInterface)->getRandomForwardLink((RomCurveDef*)state->route.nextNode, 0);
                if (RomCurve_advanceToNextSegment(&state->route, (*gRomCurveInterface)->getById(nextNode)) != 0) {
                    state->mode = CURVEFISH_MODE_WAIT;
                    state->modeTimer = 0.0f;
                    obj->anim.alpha = 0;
                    return;
                }
            }

            dx = state->route.posX - obj->anim.localPosX;
            dy = (state->route.posY + (f32)(u32)placement->targetYOffset) - obj->anim.localPosY;
            dz = state->route.posZ - obj->anim.localPosZ;
            directionMagnitude = sqrtf(dx * dx + dy * dy + dz * dz);
            dx /= directionMagnitude;
            dy /= directionMagnitude;
            dz /= directionMagnitude;

            obj->anim.localPosX += dx * state->speed;
            obj->anim.localPosY += dy * state->speed;
            obj->anim.localPosZ += dz * state->speed;

            targetYaw = (s16)getAngle(dx, dz);
            yawDelta = targetYaw - ((u16)(obj->anim.rotX));
            if (yawDelta > CURVEFISH_YAW_HALF_TURN) {
                yawDelta -= CURVEFISH_YAW_WRAP;
            }
            if (yawDelta < -CURVEFISH_YAW_HALF_TURN) {
                yawDelta += CURVEFISH_YAW_WRAP;
            }
            if (yawDelta > CURVEFISH_MAX_YAW_TURN) {
                obj->anim.rotX += CURVEFISH_MAX_YAW_TURN;
            } else if (yawDelta < -CURVEFISH_MAX_YAW_TURN) {
                obj->anim.rotX -= CURVEFISH_MAX_YAW_TURN;
            } else {
                obj->anim.rotX = targetYaw;
            }
        }

        ObjAnim_AdvanceCurrentMove(obj, state->animStep, timeDelta, NULL);
        state->moveTimer += timeDelta;
    default:
        return;
    }
}

void CurveFish_init(GameObject* obj, CurveFishPlacement* placement) {
    CurveFishState* state;
    u32 flags;

    state = obj->extra;
    flags = obj->objectFlags;
    flags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->objectFlags = flags;
    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase *
                                ((f32)(u32)placement->rootMotionScalePercent / CURVEFISH_SPEED_PERCENT_SCALE);
    state->mode = CURVEFISH_MODE_SPAWN;
    state->maxSpeed = (f32)(u32)placement->speedChange / CURVEFISH_SPEED_PERCENT_SCALE;
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
