/*
 * Grimble object (DLL slot 208).
 *
 * Grimble attaches to the nearest path object, patrols within its path
 * bounds, reverses at edges, and transitions into target-aware attacks.
 */
#include "dlls/objects/208_Grimble.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/objfx_api.h"
#include "main/frame_timing.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/gamebits_api.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "sys/objects/lifecycle.h"

#define GRIMBLE_OBJECT_GROUP         3
#define GRIMBLE_PATH_OBJECT_GROUP    0x17
#define GRIMBLE_PARTICLE_TRAIL_FLAGS 0x60
#define GRIMBLE_PARTICLE_BURST_FLAG  0x100
#define GRIMBLE_BONE_EFFECT_ID       0x52a
#define GRIMBLE_PATH_MIN_PROGRESS    0.3f
#define GRIMBLE_PATH_MAX_PROGRESS    6.7f
#define GRIMBLE_PATH_SAMPLE_OFFSET   0.1f
#define GRIMBLE_TARGET_MIN_PROGRESS  1.0f
#define GRIMBLE_TARGET_MAX_PROGRESS  6.0f
void* gGrimbleStateHandlersB[6];

int grimble_stateHandlerB05(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;

    if (state->baddie.moveJustStartedB != 0) {
        objectState->subMode = 0;
        mainSetBits(objectState->gameBitB, 0);
        mainSetBits(objectState->gameBitA, 1);
    }
    return 0;
}

int grimble_stateHandlerB04(GameObject* obj, GroundBaddieState* state) {
    if (state->baddie.moveJustStartedB != 0) {
        (*gPlayerInterface)->setState(obj, state, 8);
        state->baddie.targetObj = NULL;
        state->baddie.physicsActive = 0;
        state->baddie.hasTarget = 0;
        ObjHits_DisableObject(obj);
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    if (obj->anim.alpha == 0) {
        if (obj->anim.placementData == NULL) {
            Obj_FreeObject(obj);
            return 0;
        }
        return 6;
    }
    return 0;
}

int grimble_stateHandlerB03(GameObject* obj, GroundBaddieState* state) {
    (void)obj;

    if (state->baddie.hitPoints < 1) {
        return 5;
    }
    return 1;
}

int grimble_stateHandlerB02(GameObject* obj, GroundBaddieState* state) {
    GameObject* target;
    f32 dx;
    f32 dz;
    f32 absoluteDistance;
    u32 relativeAngle;

    target = *(GameObject**)&state->baddie.targetObj;
    if (target == NULL) {
        (*gPlayerInterface)->setState(obj, state, 0);
        return 1;
    }
    if (state->baddie.controlMode != 6) {
        dx = obj->anim.localPosX - target->anim.localPosX;
        dz = obj->anim.localPosZ - target->anim.localPosZ;
        relativeAngle = (getAngle(dx, dz) - *(s16*)obj) & 0xffff;
        if (relativeAngle > 0x4000 && relativeAngle < 0xc000) {
            dx = -100.0f;
        } else {
            dx = sqrtf(dx * dx + dz * dz) - 45.0f;
        }
        absoluteDistance = dx < 0.0f ? -dx : dx;
        if (absoluteDistance < 1.0f &&
            (state->baddie.controlMode == 1 || (state->baddie.controlMode == 5 && state->baddie.moveDone != 0))) {
            (*gPlayerInterface)->setState(obj, state, 6);
        } else if (state->baddie.controlMode != 1) {
            if (dx > 2.5f) {
                if (state->baddie.controlMode != 4 && (state->baddie.controlMode != 5 || state->baddie.moveDone != 0)) {
                    (*gPlayerInterface)->setState(obj, state, 1);
                }
            }
            if (dx < -2.5f) {
                (*gPlayerInterface)->setState(obj, state, 1);
            }
        }
        if (state->baddie.controlMode == 1) {
            state->baddie.moveSpeed = (dx > 0.0f) ? 0.04f : -0.07f;
        }
    }
    return 0;
}

int grimble_stateHandlerB01(GameObject* obj, GroundBaddieState* state) {
    if (state->baddie.moveJustStartedB != 0) {
        (*gPlayerInterface)->setState(obj, state, 9);
    }
    if (state->baddie.moveDone != 0) {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerB00(GameObject* obj, GroundBaddieState* state) {
    u16 zone;
    u16 unusedAngle;
    u16 distance;

    if (state->baddie.targetObj != NULL && state->baddie.controlMode != 2) {
        if ((f32)state->baddie.stateTimer > 4.0f * timeDelta) {
            (*gBaddieControlInterface)
                ->getTargetGeometry(obj, (GameObject*)state->baddie.targetObj, 16, &zone, &unusedAngle, &distance);
            if (zone < 4 || zone > 11) {
                return 3;
            }
            (*gPlayerInterface)->setState(obj, state, 2);
            state->baddie.moveSpeed = 0.028f;
            state->baddie.moveDone = 0;
        }
    }
    return 0;
}

int grimble_stateHandlerA09(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState;
    f32 speed;

    objectState = obj->extra;
    state->baddie.stateTag = 0;
    state->baddie.moveSpeed = 0.01f;
    speed = 0.0f;
    state->baddie.animSpeedA = speed;
    state->baddie.animSpeedB = speed;
    if (state->baddie.moveJustStartedA != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_seal4_c_27c);
        if (state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 2, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        state->baddie.moveSpeed = 0.025f;
        state->baddie.moveDone = 0;
        obj->anim.alpha = 0xff;
        objectState->flags400 |= 0x100;
    }
    if (state->baddie.moveDone != 0) {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerA08(GameObject* obj, GroundBaddieState* state) {
    GroundBaddieState* objectState = obj->extra;

    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 8, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = 0.048f;
    if (((s32)state->baddie.eventFlags & BADDIE_EVENT_LANDING) != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16_233);
        state->baddie.eventFlags &= ~BADDIE_EVENT_LANDING;
        (*gBaddieControlInterface)->spawnChild(obj, objectState->triggerId, -1, 1);
    }
    return 0;
}

int grimble_stateHandlerA07(GameObject* obj, GroundBaddieState* state) {
    GrimbleControl* control;
    s16 pathRotX;
    int rotationDelta;
    f32 speed;

    control = ((GroundBaddieState*)obj->extra)->control;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 7, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    if (state->baddie.moveJustStartedA != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_ms_windlift_loop);
    }
    state->baddie.moveSpeed = 0.018f;
    pathRotX = control->baseRotX;
    rotationDelta = obj->anim.rotX - (pathRotX & 0xffff);
    if (rotationDelta > 0x8000) {
        rotationDelta -= 0xffff;
    }
    if (rotationDelta < -0x8000) {
        rotationDelta += 0xffff;
    }
    obj->anim.rotX = pathRotX;
    if (rotationDelta > 0x3ffc || rotationDelta < -0x3ffc) {
        obj->anim.rotX += 0x8000;
    }
    speed = 0.0f;
    state->baddie.animSpeedA = speed;
    state->baddie.animSpeedB = speed;
    if (state->baddie.moveDone != 0) {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerA06(GameObject* obj, GroundBaddieState* state, f32 speed) {
    GrimbleControl* control;
    f64 horizontalRunDouble;
    f32 horizontalRun;
    struct {
        f32 x, y, z;
    } aheadSample;
    struct {
        f32 x, y, z;
    } pathDelta;

    control = ((GroundBaddieState*)obj->extra)->control;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 9;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (randomGetRange(0, 100) < 50) {
        if (state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
    } else if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 4, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = 0.03f;
    (*gPlayerInterface)->updateAnimRootMotion(obj, state, speed, 1);
    control->pathObj->pathInterface->callbacks->advance(control->pathObj, &control->pathProgress,
                                                        state->baddie.animSpeedA * (f32)(1 - (control->reversed << 1)));
    if (control->pathProgress < GRIMBLE_PATH_MIN_PROGRESS) {
        control->pathProgress = GRIMBLE_PATH_MIN_PROGRESS;
    } else if (control->pathProgress > GRIMBLE_PATH_MAX_PROGRESS) {
        control->pathProgress = GRIMBLE_PATH_MAX_PROGRESS;
    }
    control->pathObj->pathInterface->callbacks->sample(
        control->pathObj, control->pathProgress - GRIMBLE_PATH_SAMPLE_OFFSET, &pathDelta.x, &pathDelta.y, &pathDelta.z);
    control->pathObj->pathInterface->callbacks->sample(control->pathObj,
                                                       GRIMBLE_PATH_SAMPLE_OFFSET + control->pathProgress,
                                                       &aheadSample.x, &aheadSample.y, &aheadSample.z);
    pathDelta.x -= aheadSample.x;
    pathDelta.y -= aheadSample.y;
    pathDelta.z -= aheadSample.z;
    horizontalRun = sqrtf(pathDelta.x * pathDelta.x + pathDelta.z * pathDelta.z);
    horizontalRunDouble = horizontalRun;
    pathDelta.x = horizontalRun;
    {
        int pathAngle = (s16)getAngle(pathDelta.y, horizontalRunDouble);

        obj->anim.rotY = pathAngle * ((control->reversed << 1) - 1);
    }
    if (state->baddie.moveDone != 0) {
        return 5;
    }
    return 0;
}

int grimble_stateHandlerA05(GameObject* obj, GroundBaddieState* state) {
    GrimbleControl* control;
    f64 horizontalRunDouble;
    f32 horizontalRun;
    struct {
        f32 x, y, z;
    } aheadSample;
    struct {
        f32 x, y, z;
    } pathDelta;

    control = ((GroundBaddieState*)obj->extra)->control;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 6, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = 0.03f;
    control->pathObj->pathInterface->callbacks->sample(
        control->pathObj, control->pathProgress - GRIMBLE_PATH_SAMPLE_OFFSET, &pathDelta.x, &pathDelta.y, &pathDelta.z);
    control->pathObj->pathInterface->callbacks->sample(control->pathObj,
                                                       GRIMBLE_PATH_SAMPLE_OFFSET + control->pathProgress,
                                                       &aheadSample.x, &aheadSample.y, &aheadSample.z);
    pathDelta.x -= aheadSample.x;
    pathDelta.y -= aheadSample.y;
    pathDelta.z -= aheadSample.z;
    horizontalRun = sqrtf(pathDelta.x * pathDelta.x + pathDelta.z * pathDelta.z);
    horizontalRunDouble = horizontalRun;
    pathDelta.x = horizontalRun;
    {
        int pathAngle = (s16)getAngle(pathDelta.y, horizontalRunDouble);

        obj->anim.rotY = pathAngle * ((control->reversed << 1) - 1);
    }
    return 0;
}

int grimble_stateHandlerA04(GameObject* obj, GroundBaddieState* state) {
    GrimbleControl* control;
    f64 horizontalRunDouble;
    f32 horizontalRun;
    struct {
        f32 x, y, z;
    } aheadSample;
    struct {
        f32 x, y, z;
    } pathDelta;

    control = ((GroundBaddieState*)obj->extra)->control;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 5, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = 0.03f;
    control->pathObj->pathInterface->callbacks->sample(
        control->pathObj, control->pathProgress - GRIMBLE_PATH_SAMPLE_OFFSET, &pathDelta.x, &pathDelta.y, &pathDelta.z);
    control->pathObj->pathInterface->callbacks->sample(control->pathObj,
                                                       GRIMBLE_PATH_SAMPLE_OFFSET + control->pathProgress,
                                                       &aheadSample.x, &aheadSample.y, &aheadSample.z);
    pathDelta.x -= aheadSample.x;
    pathDelta.y -= aheadSample.y;
    pathDelta.z -= aheadSample.z;
    horizontalRun = sqrtf(pathDelta.x * pathDelta.x + pathDelta.z * pathDelta.z);
    horizontalRunDouble = horizontalRun;
    pathDelta.x = horizontalRun;
    {
        int pathAngle = (s16)getAngle(pathDelta.y, horizontalRunDouble);

        obj->anim.rotY = pathAngle * ((control->reversed << 1) - 1);
    }
    if (state->baddie.moveDone != 0) {
        return 6;
    }
    return 0;
}

int grimble_stateHandlerA03(GameObject* obj, GroundBaddieState* state) {
    GrimbleControl* control;
    f64 horizontalRunDouble;
    f32 horizontalRun;
    struct {
        f32 x, y, z;
    } aheadSample;
    struct {
        f32 x, y, z;
    } pathDelta;

    control = ((GroundBaddieState*)obj->extra)->control;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 2, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = 0.025f;
    control->pathObj->pathInterface->callbacks->sample(
        control->pathObj, control->pathProgress - GRIMBLE_PATH_SAMPLE_OFFSET, &pathDelta.x, &pathDelta.y, &pathDelta.z);
    control->pathObj->pathInterface->callbacks->sample(control->pathObj,
                                                       GRIMBLE_PATH_SAMPLE_OFFSET + control->pathProgress,
                                                       &aheadSample.x, &aheadSample.y, &aheadSample.z);
    pathDelta.x -= aheadSample.x;
    pathDelta.y -= aheadSample.y;
    pathDelta.z -= aheadSample.z;
    horizontalRun = sqrtf(pathDelta.x * pathDelta.x + pathDelta.z * pathDelta.z);
    horizontalRunDouble = horizontalRun;
    pathDelta.x = horizontalRun;
    {
        int pathAngle = (s16)getAngle(pathDelta.y, horizontalRunDouble);

        obj->anim.rotY = pathAngle * ((control->reversed << 1) - 1);
    }
    if (state->baddie.moveDone != 0) {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerA02(GameObject* obj, char* state, f32 timeStep) {
    u16 zone;
    u16 unusedAngle;
    u16 distance;
    f32 aheadZ, aheadY, aheadX, deltaZ, deltaY, deltaX;
    f32 speed;
    f32 pathVelocity;
    s16 pathAngle;
    double horizontalRunDouble;
    f32 horizontalRun;
    GrimbleControl* controlData;

    controlData = (GrimbleControl*)((GroundBaddieState*)obj->extra)->control;
    if (((GroundBaddieState*)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 3, 0.0f, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = 0.03f;
    (*gPlayerInterface)->updateAnimRootMotion(obj, state, timeStep, 9);
    controlData->pathObj->pathInterface->callbacks->advance(controlData->pathObj, &controlData->pathProgress,
                                                            ((GroundBaddieState*)state)->baddie.animSpeedA *
                                                                (f32)(1 - (controlData->reversed << 1)));
    if (controlData->pathProgress < GRIMBLE_PATH_MIN_PROGRESS) {
        controlData->pathProgress = GRIMBLE_PATH_MIN_PROGRESS;
    } else if (controlData->pathProgress > GRIMBLE_PATH_MAX_PROGRESS) {
        controlData->pathProgress = GRIMBLE_PATH_MAX_PROGRESS;
    }
    controlData->pathObj->pathInterface->callbacks->sample(
        controlData->pathObj, controlData->pathProgress - GRIMBLE_PATH_SAMPLE_OFFSET, &deltaX, &deltaY, &deltaZ);
    controlData->pathObj->pathInterface->callbacks->sample(
        controlData->pathObj, GRIMBLE_PATH_SAMPLE_OFFSET + controlData->pathProgress, &aheadX, &aheadY, &aheadZ);
    deltaX -= aheadX;
    deltaY -= aheadY;
    deltaZ -= aheadZ;
    horizontalRun = sqrtf(deltaX * deltaX + deltaZ * deltaZ);
    horizontalRunDouble = horizontalRun;
    deltaX = horizontalRun;
    pathAngle = getAngle(deltaY, horizontalRunDouble);
    obj->anim.rotY =
        (1.0f - 2.0f * obj->anim.currentMoveProgress) * (f32)(s16)(pathAngle * ((controlData->reversed << 1) - 1));
    if (((GroundBaddieState*)state)->baddie.moveDone != 0) {
        (*gBaddieControlInterface)
            ->getTargetGeometry(obj, (GameObject*)((GroundBaddieState*)state)->baddie.targetObj, 0x10, &zone,
                                &unusedAngle, &distance);
        controlData->reversed = 1 - *(u8*)&controlData->reversed;
        obj->anim.rotX = controlData->baseRotX + (!controlData->reversed << 15);
        speed = randomGetRange(50, 100) / 100.0f;
        pathVelocity = (f32)((controlData->reversed << 1) - 1) * speed;
        if (zone < 4 || zone > 11) {
            if (distance > 500) {
                pathVelocity *= 1.0f + distance / 100.0f;
            } else {
                pathVelocity *= 1.0f + distance / 300.0f;
            }
        }
        controlData->targetProgress = controlData->pathProgress - pathVelocity;
        speed = controlData->targetProgress;
        speed = (speed > GRIMBLE_TARGET_MIN_PROGRESS) ? speed : GRIMBLE_TARGET_MIN_PROGRESS;
        controlData->targetProgress = speed;
        speed = controlData->targetProgress;
        speed = (speed < GRIMBLE_TARGET_MAX_PROGRESS) ? speed : GRIMBLE_TARGET_MAX_PROGRESS;
        controlData->targetProgress = speed;
        return 4;
    }
    return 0;
}

int grimble_stateHandlerA01(GameObject* obj, char* state, f32 timeStep) {
    f32 aheadZ, aheadY, aheadX, deltaZ, deltaY, deltaX;
    u8 hitEdge;
    s16 pathAngle;
    double horizontalRunDouble;
    f32 horizontalRun;
    GrimbleControl* controlData;

    controlData = (GrimbleControl*)((GroundBaddieState*)obj->extra)->control;
    if (((GroundBaddieState*)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    (*gPlayerInterface)->updateAnimRootMotion(obj, state, timeStep, 0);
    if ((((GroundBaddieState*)state)->baddie.eventFlags & BADDIE_EVENT_FOOTSTEP) != 0) {
        ((GroundBaddieState*)state)->baddie.eventFlags =
            ((GroundBaddieState*)state)->baddie.eventFlags & ~BADDIE_EVENT_FOOTSTEP;
        Sfx_PlayFromObject(obj, SFXTRIG_mv_persquk1);
    }
    controlData->pathObj->pathInterface->callbacks->advance(
        controlData->pathObj, &controlData->pathProgress,
        50.4f * (((GroundBaddieState*)state)->baddie.moveSpeed * (f32)(1 - (controlData->reversed << 1))));
    if (controlData->pathProgress < GRIMBLE_PATH_MIN_PROGRESS) {
        controlData->pathProgress = GRIMBLE_PATH_MIN_PROGRESS;
        hitEdge = 1;
    } else if (controlData->pathProgress > GRIMBLE_PATH_MAX_PROGRESS) {
        controlData->pathProgress = GRIMBLE_PATH_MAX_PROGRESS;
        hitEdge = 1;
    } else {
        hitEdge = 0;
    }
    if (hitEdge != 0) {
        return 7;
    }
    controlData->pathObj->pathInterface->callbacks->sample(
        controlData->pathObj, controlData->pathProgress - GRIMBLE_PATH_SAMPLE_OFFSET, &deltaX, &deltaY, &deltaZ);
    controlData->pathObj->pathInterface->callbacks->sample(
        controlData->pathObj, GRIMBLE_PATH_SAMPLE_OFFSET + controlData->pathProgress, &aheadX, &aheadY, &aheadZ);
    deltaX -= aheadX;
    deltaY -= aheadY;
    deltaZ -= aheadZ;
    horizontalRun = sqrtf(deltaX * deltaX + deltaZ * deltaZ);
    horizontalRunDouble = horizontalRun;
    deltaX = horizontalRun;
    pathAngle = getAngle(deltaY, horizontalRunDouble);
    obj->anim.rotY = pathAngle * ((controlData->reversed << 1) - 1);
    return 0;
}

int grimble_stateHandlerA00(GameObject* obj, char* state, f32 timeStep) {
    u16 zone;
    u16 unusedAngle;
    u16 distance;
    f32 aheadZ, aheadY, aheadX, deltaZ, deltaY, deltaX;
    s16 pathAngle;
    double horizontalRunDouble;
    f32 horizontalRun;
    GrimbleControl* controlData;

    controlData = (GrimbleControl*)((GroundBaddieState*)obj->extra)->control;
    if (((GroundBaddieState*)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = 0.03f;
    (*gPlayerInterface)->updateAnimRootMotion(obj, state, timeStep, 1);
    controlData->pathObj->pathInterface->callbacks->advance(controlData->pathObj, &controlData->pathProgress,
                                                            ((GroundBaddieState*)state)->baddie.animSpeedA *
                                                                (f32)(1 - (controlData->reversed << 1)));
    if (controlData->pathProgress < GRIMBLE_PATH_MIN_PROGRESS) {
        controlData->pathProgress = GRIMBLE_PATH_MIN_PROGRESS;
    } else if (controlData->pathProgress > GRIMBLE_PATH_MAX_PROGRESS) {
        controlData->pathProgress = GRIMBLE_PATH_MAX_PROGRESS;
    }
    (*gBaddieControlInterface)
        ->getTargetGeometry(obj, (GameObject*)((GroundBaddieState*)state)->baddie.targetObj, 0x10, &zone, &unusedAngle,
                            &distance);
    if (zone > 3 && zone < 12 && distance > 400 && controlData->pathProgress > 2.0f &&
        controlData->pathProgress < 5.0f) {
        return 3;
    }
    if ((controlData->reversed ^ (controlData->pathProgress >= controlData->targetProgress)) != 0 &&
        ((GroundBaddieState*)state)->baddie.moveDone != 0) {
        return 3;
    }
    if ((((GroundBaddieState*)state)->baddie.eventFlags & BADDIE_EVENT_FOOTSTEP) != 0) {
        ((GroundBaddieState*)state)->baddie.eventFlags =
            ((GroundBaddieState*)state)->baddie.eventFlags & ~BADDIE_EVENT_FOOTSTEP;
        Sfx_PlayFromObject(obj, SFXTRIG_mv_persquk1);
    }
    controlData->pathObj->pathInterface->callbacks->sample(
        controlData->pathObj, controlData->pathProgress - GRIMBLE_PATH_SAMPLE_OFFSET, &deltaX, &deltaY, &deltaZ);
    controlData->pathObj->pathInterface->callbacks->sample(
        controlData->pathObj, GRIMBLE_PATH_SAMPLE_OFFSET + controlData->pathProgress, &aheadX, &aheadY, &aheadZ);
    deltaX -= aheadX;
    deltaY -= aheadY;
    deltaZ -= aheadZ;
    horizontalRun = sqrtf(deltaX * deltaX + deltaZ * deltaZ);
    horizontalRunDouble = horizontalRun;
    deltaX = horizontalRun;
    pathAngle = getAngle(deltaY, horizontalRunDouble);
    obj->anim.rotY = pathAngle * ((controlData->reversed << 1) - 1);
    return 0;
}

int grimble_animEventCallback(void) {
    return 0;
}

void grimble_attachNearestPath(GameObject* obj) {
    int pathObjectCount;
    f32 pathDistance;
    f32 candidateProgress;
    f32 pathQueryAux;
    f32 targetProgress;
    GrimblePathObject** pathObjects;
    GroundBaddieState* state;
    int pathObjectIndex;
    int rotationDelta;
    int sameDirection;
    GrimbleControl* control;

    state = obj->extra;
    pathObjects = (GrimblePathObject**)objGetAllOfType(GRIMBLE_PATH_OBJECT_GROUP, &pathObjectCount);
    if (pathObjectCount != 0) {
        control = state->control;
        control->candidatePathObj = 0;
        control->nearestDist = 200.0f;
        for (pathObjectIndex = 0; pathObjectIndex < pathObjectCount; pathObjectIndex++) {
            if (pathObjects[pathObjectIndex]->pathInterface->callbacks->findNearest(
                    pathObjects[pathObjectIndex], obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                    &pathDistance, &candidateProgress, &pathQueryAux) != 0 &&
                pathDistance < control->nearestDist) {
                control->candidatePathObj = pathObjects[pathObjectIndex];
                control->nearestDist = pathDistance;
                control->candidateProgress = candidateProgress;
            }
        }
        if (control->candidatePathObj != NULL) {
            control->pathObj = control->candidatePathObj;
            control->pathProgress = control->candidateProgress;
            control->pathObj->pathInterface->callbacks->initialise(control->pathObj, control->pathState);
            control->pathObj->pathInterface->callbacks->sample(
                control->pathObj, control->pathProgress, &control->pathPosX, &control->pathPosY, &control->pathPosZ);
            control->baseRotX = control->pathObj->pathInterface->callbacks->getRotation(control->pathObj);
            control->savedPathProgress = control->pathProgress;
            control->unk46 = 0;
            control->anchorPosY = control->pathPosY;
            control->currentPosY = obj->anim.localPosY;
            control->posYDelta = control->anchorPosY - control->currentPosY;
            rotationDelta = obj->anim.rotX - (u16)control->baseRotX;
            if (rotationDelta > 0x8000) {
                rotationDelta -= 0xffff;
            }
            if (rotationDelta < -0x8000) {
                rotationDelta += 0xffff;
            }
            sameDirection = 0;
            if (rotationDelta <= 0x3ffc && rotationDelta >= -0x3ffc) {
                sameDirection = 1;
            }
            control->reversed = sameDirection;
            obj->anim.rotX = control->baseRotX + (!control->reversed << 15);
            targetProgress =
                control->pathProgress - (f32)((control->reversed << 1) - 1) * (randomGetRange(10, 60) / 10.0f);
            control->targetProgress = targetProgress;
            targetProgress = control->targetProgress;
            targetProgress =
                (targetProgress > GRIMBLE_TARGET_MIN_PROGRESS) ? targetProgress : GRIMBLE_TARGET_MIN_PROGRESS;
            control->targetProgress = targetProgress;
            targetProgress = control->targetProgress;
            targetProgress =
                (targetProgress < GRIMBLE_TARGET_MAX_PROGRESS) ? targetProgress : GRIMBLE_TARGET_MAX_PROGRESS;
            control->targetProgress = targetProgress;
        }
    }
}

int grimble_getExtraSize(void) {
    return sizeof(GroundBaddieState) + sizeof(GrimbleControl);
}

int grimble_getObjectTypeId(void) {
    return 0x59;
}

void grimble_free(GameObject* obj) {
    GroundBaddieState* state = obj->extra;

    objFreeObjectType(obj, GRIMBLE_OBJECT_GROUP);
    (*gBaddieControlInterface)->releaseState(obj, state, 0);
}

void grimble_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    GroundBaddieState* state = obj->extra;
    GrimbleControl* control = state->control;

    if (visible == 0 || obj->userData1 != 0) {
        return;
    }
    objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    if (control->unk50 > 0.0f) {
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, GRIMBLE_BONE_EFFECT_ID, NULL, 100, NULL);
    }
    if ((state->flags400 & GRIMBLE_PARTICLE_TRAIL_FLAGS) != 0) {
        objDoParticleFx(obj, 1.0f, 3, state->glowAlpha, 0);
    }
    if ((state->flags400 & GRIMBLE_PARTICLE_BURST_FLAG) != 0) {
        objDoParticleFx(obj, 1.0f, 4, state->glowAlpha, 0);
        state->flags400 &= ~GRIMBLE_PARTICLE_BURST_FLAG;
    }
}

void grimble_hitDetect(GameObject* obj) {
    (*gPlayerInterface)->updateVelocityState(obj, obj->extra, gGrimbleStateHandlersA);
}

void grimble_update(GameObject* obj) {
    GroundBaddieState* state;
    GrimbleControl* control;
    ObjPlacement* placement;

    state = obj->extra;
    control = state->control;
    placement = (ObjPlacement*)obj->anim.placementData;
    if (obj->userData1 != 0) {
        if ((*gMapEventInterface)->shouldNotSaveTime(placement->ident) != 0) {
            (*gBaddieControlInterface)->initGroundBaddie(obj, (u8*)placement, (u8*)state, 0xa, 6, 0x10e, 0x36, 20.0f);
            state->baddie.substate = 1;
            state->baddie.moveJustStartedB = 1;
            obj->anim.alpha = 0;
        }
    } else if (control->candidatePathObj != NULL) {
        GameObject* target;
        int hitReaction;

        (*gPlayerInterface)->update(obj, state, 1.0f, 1.0f, gGrimbleStateHandlersA, gGrimbleStateHandlersB);
        control->pathObj->pathInterface->callbacks->sample(
            control->pathObj, control->pathProgress, &obj->anim.localPosX, &obj->anim.localPosY, &obj->anim.localPosZ);
        (*gBaddieControlInterface)
            ->processMessages(obj, state, &state->routeNav, state->gameBitB, &state->subMode, 0, 0, 0);
        hitReaction = (*gBaddieControlInterface)
                          ->updateHitReaction(obj, state, &state->routeNav, state->gameBitB, gGrimbleHitReactionMoves,
                                              gGrimbleHitReactionDamage, 3, NULL);
        if (hitReaction == 0xe) {
            state->subMode = 2;
            state->baddie.targetObj = Obj_GetPlayerObject();
        }
        if (state->baddie.targetObj != NULL || state->baddie.hitPoints == 0) {
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= 1;
            if ((*gBaddieControlInterface)->shouldDropTarget(obj, state, (f32)state->aggroRange, 1) != 0) {
                state->baddie.targetObj = 0;
            }
        } else {
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~1;
            target = (*gBaddieControlInterface)->findAggroTarget(obj, state, (f32)state->aggroRange, 0x8000);
            if (target != NULL) {
                state->baddie.targetObj = target;
                state->baddie.hasTarget = 0;
            }
        }
    } else {
        grimble_attachNearestPath(obj);
    }
}

void* gGrimbleStateHandlersA[10];

void grimble_init(GameObject* obj, ObjPlacement* placement, int flags) {
    GroundBaddieState* state = obj->extra;
    u8 initFlags = 2;

    if (flags != 0) {
        initFlags |= 1;
    }
    (*gBaddieControlInterface)->initGroundBaddie(obj, (u8*)placement, (u8*)state, 0, 0, 0, initFlags, 20.0f);
    obj->animEventCallback = grimble_animEventCallback;
    (*gPlayerInterface)->setState(obj, state, 0);
    state->baddie.substate = 0;
    state->baddie.animSpeedA = 0.0f;
    ((GrimbleControl*)state->control)->candidatePathObj = 0;
}

void grimble_release(void) {
}

void grimble_initialise(void) {
    grimble_initialiseStateHandlerTables();
}

void grimble_initialiseStateHandlerTables(void) {
    gGrimbleStateHandlersA[0] = grimble_stateHandlerA00;
    gGrimbleStateHandlersA[1] = grimble_stateHandlerA01;
    gGrimbleStateHandlersA[2] = grimble_stateHandlerA02;
    gGrimbleStateHandlersA[3] = grimble_stateHandlerA03;
    gGrimbleStateHandlersA[4] = grimble_stateHandlerA04;
    gGrimbleStateHandlersA[5] = grimble_stateHandlerA05;
    gGrimbleStateHandlersA[6] = grimble_stateHandlerA06;
    gGrimbleStateHandlersA[7] = grimble_stateHandlerA07;
    gGrimbleStateHandlersA[8] = grimble_stateHandlerA08;
    gGrimbleStateHandlersA[9] = grimble_stateHandlerA09;
    gGrimbleStateHandlersB[0] = grimble_stateHandlerB00;
    gGrimbleStateHandlersB[1] = grimble_stateHandlerB01;
    gGrimbleStateHandlersB[2] = grimble_stateHandlerB02;
    gGrimbleStateHandlersB[3] = grimble_stateHandlerB03;
    gGrimbleStateHandlersB[4] = grimble_stateHandlerB04;
    gGrimbleStateHandlersB[5] = grimble_stateHandlerB05;
}

int gGrimbleHitReactionMoves[30] = {
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
};

u8 gGrimbleHitReactionDamage[32] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,   0,
};

ObjectDescriptor gGrimbleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)grimble_initialise,
    (ObjectDescriptorCallback)grimble_release,
    0,
    (ObjectDescriptorCallback)grimble_init,
    (ObjectDescriptorCallback)grimble_update,
    (ObjectDescriptorCallback)grimble_hitDetect,
    (ObjectDescriptorCallback)grimble_render,
    (ObjectDescriptorCallback)grimble_free,
    (ObjectDescriptorCallback)grimble_getObjectTypeId,
    grimble_getExtraSize,
};
