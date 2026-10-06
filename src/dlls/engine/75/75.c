/*
 * DLL 75 / 0x4B - climbing camera mode.
 */
#include "main/dll/dll_004B_cameramodeclimb.h"

#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_0042_cameramodenormal.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "string.h"

CameraModeClimbState* gCameraModeClimbState;

static f32 camClimb_u32AsFloat(u32 value);
static f32 camClimb_s32AsFloat(s32 value);

void CameraModeClimb_initialise(void) {
}

void CameraModeClimb_release(void) {
}

void CameraModeClimb_init(CameraObject* camera, int mode, CameraModeClimbTransition* transition) {
    f32 outX;
    f32 outY;
    f32 outZ;
    f32 defaultDistXZ;
    f32 defaultDistB;
    f32 defaultDistA;
    f32 defaultMinHeight;
    f32 defaultMaxHeight;
    f32 defaultRelPos;
    CamcontrolDefaultHandlerEntry* handler;

    if (gCameraModeClimbState == NULL) {
        gCameraModeClimbState = (CameraModeClimbState*)mmAlloc(sizeof(CameraModeClimbState), 0xf, 0);
    }
    switch (mode) {
    case 2:
        gCameraModeClimbState->startRelativePosition = gCameraModeClimbState->relativePosition;
        gCameraModeClimbState->startMinHeight = gCameraModeClimbState->minHeight;
        gCameraModeClimbState->startMaxHeight = gCameraModeClimbState->maxHeight;
        gCameraModeClimbState->startDistance = gCameraModeClimbState->targetDistance;
        gCameraModeClimbState->targetRelativePosition = (u16)(int)(182.04445f * (f32)transition->relativePosition);
        gCameraModeClimbState->endMinHeight = transition->minHeight;
        gCameraModeClimbState->endMaxHeight = transition->maxHeight;
        gCameraModeClimbState->endDistance = transition->distance;
        gCameraModeClimbState->transitionTimer = (s16)transition->duration;
        gCameraModeClimbState->transitionDuration = (s16)transition->duration;
        break;
    case 1:
    default:
        memset(gCameraModeClimbState, 0, sizeof(CameraModeClimbState));
        handler = (*gCameraInterface)->getDefaultHandlerEntry();
        handler->handler->vtable->getSettings(&defaultDistB, &defaultDistA, &defaultMinHeight, &defaultMaxHeight,
                                              &defaultRelPos);
        (*gCameraInterface)
            ->getRelativePosition(camera, &outX, &outY, &outZ, &defaultDistXZ,
                                  (f32)(u16)gCameraModeClimbState->relativePosition, 0);
        gCameraModeClimbState->startRelativePosition = defaultRelPos;
        gCameraModeClimbState->startMinHeight = defaultMinHeight;
        gCameraModeClimbState->startMaxHeight = defaultMaxHeight;
        gCameraModeClimbState->startDistance = defaultDistXZ;
        gCameraModeClimbState->targetRelativePosition = 30;
        gCameraModeClimbState->endMinHeight = -50.0f;
        gCameraModeClimbState->endMaxHeight = 50.0f;
        gCameraModeClimbState->endDistance = 0.5f * (defaultDistA + defaultDistB);
        gCameraModeClimbState->transitionTimer = 60;
        gCameraModeClimbState->transitionDuration = 60;
        gCameraModeClimbState->smoothedDistance = defaultDistXZ;
        gCameraModeClimbState->heightAdjustRate = 0.05f;
        break;
    }
}

void CameraModeClimb_update(CameraObject* camera) {
    f32 blend;
    f32 targetY;
    f32 maxCameraY;
    f32 minCameraY;
    u32 angle;
    int angleDelta;
    GameObject* target;
    f32 trigValue;
    f32 relX;
    f32 value;
    f32 relZ;
    f32 distance;
    f32 traceFrom[3];
    f32 traceOut[3];
    TrackHitResults traceWork;

    target = (GameObject*)camera->focusObject;
    if (gCameraModeClimbState->transitionTimer != 0) {
        gCameraModeClimbState->transitionTimer -= framesThisStep;
        if (gCameraModeClimbState->transitionTimer < 0) {
            gCameraModeClimbState->transitionTimer = 0;
        }
        blend = (f32)(s32)(gCameraModeClimbState->transitionDuration - gCameraModeClimbState->transitionTimer) /
                (f32)(s32)gCameraModeClimbState->transitionDuration;
        gCameraModeClimbState->relativePosition =
            blend * camClimb_s32AsFloat(gCameraModeClimbState->targetRelativePosition -
                                        gCameraModeClimbState->startRelativePosition) +
            camClimb_u32AsFloat(gCameraModeClimbState->startRelativePosition);
        gCameraModeClimbState->targetDistance =
            blend * (gCameraModeClimbState->endDistance - gCameraModeClimbState->startDistance) +
            gCameraModeClimbState->startDistance;
        gCameraModeClimbState->minHeight =
            blend * (gCameraModeClimbState->endMinHeight - gCameraModeClimbState->startMinHeight) +
            gCameraModeClimbState->startMinHeight;
        gCameraModeClimbState->maxHeight =
            blend * (gCameraModeClimbState->endMaxHeight - gCameraModeClimbState->startMaxHeight) +
            gCameraModeClimbState->startMaxHeight;
    }
    targetY = target->anim.worldPosY;
    maxCameraY = targetY + gCameraModeClimbState->maxHeight;
    minCameraY = targetY + gCameraModeClimbState->minHeight;
    blend = camera->anim.worldPosY;
    if (blend < minCameraY) {
        value = minCameraY - blend;
    } else if (blend > maxCameraY) {
        value = maxCameraY - blend;
    } else {
        value = 0.0f;
    }
    value *= (gCameraModeClimbState->heightAdjustRate * timeDelta);
    camera->anim.worldPosY += value;
    distance = gCameraModeClimbState->targetDistance;
    distance -= gCameraModeClimbState->smoothedDistance;
    distance *= (0.03f * timeDelta);
    gCameraModeClimbState->smoothedDistance += distance;
    traceFrom[0] =
        5.0f * mathSinf((3.1415927f * camClimb_s32AsFloat(target->anim.rotX)) / 32768.0f) + target->anim.worldPosX;
    traceFrom[1] = target->anim.worldPosY;
    traceFrom[2] =
        5.0f * mathCosf((3.1415927f * camClimb_s32AsFloat(target->anim.rotX)) / 32768.0f) + target->anim.worldPosZ;
    trigValue = mathSinf((3.1415927f * camClimb_s32AsFloat(target->anim.rotX)) / 32768.0f);
    camera->anim.worldPosX = gCameraModeClimbState->smoothedDistance * trigValue + traceFrom[0];
    trigValue = mathCosf((3.1415927f * camClimb_s32AsFloat(target->anim.rotX)) / 32768.0f);
    camera->anim.worldPosZ = gCameraModeClimbState->smoothedDistance * trigValue + traceFrom[2];
    camcontrol_traceMove(traceFrom, &camera->anim.worldPosX, traceOut, &traceWork, 3, 1, 1, 4.0f);
    camera->anim.worldPosX = traceOut[0];
    camera->anim.worldPosY = traceOut[1];
    camera->anim.worldPosZ = traceOut[2];
    (*gCameraInterface)
        ->getRelativePosition(camera, &relX, &value, &relZ, &distance,
                              camClimb_u32AsFloat((u16)gCameraModeClimbState->relativePosition), 0);
    {
        int targetYaw = 0x8000 - (u16)getAngle(relX, relZ);
        angleDelta = targetYaw - (u16)camera->anim.rotX;
    }
    if (angleDelta > 0x8000) {
        angleDelta = angleDelta - 0xffff;
    }
    if (angleDelta < -0x8000) {
        angleDelta += 0xffff;
    }
    camera->anim.rotX += angleDelta;
    value = camera->anim.worldPosY -
            (target->anim.worldPosY + camClimb_u32AsFloat((u16)gCameraModeClimbState->relativePosition));
    angle = getAngle(value, distance);
    angleDelta = angle & 0xffff;
    angleDelta -= (u16)camera->anim.rotY;
    if (angleDelta > 0x8000) {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000) {
        angleDelta += 0xffff;
    }
    camera->anim.rotY += (angleDelta * framesThisStep) / 6;
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

void CameraModeClimb_free(void) {
    mm_free(gCameraModeClimbState);
    gCameraModeClimbState = NULL;
}

void CameraModeClimb_copyToCurrent(void) {
}

CameraModeClimbDescriptor gCameraModeClimbDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeClimb_initialise,
    CameraModeClimb_release,
    NULL,
    CameraModeClimb_init,
    CameraModeClimb_update,
    CameraModeClimb_free,
    CameraModeClimb_copyToCurrent,
    NULL,
};

static f32 camClimb_u32AsFloat(u32 value) {
    return (f32)value;
}

static f32 camClimb_s32AsFloat(s32 value) {
    return (f32)value;
}
