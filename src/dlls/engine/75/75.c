/*
 * DLL 75 / 0x4B - climbing camera mode.
 */
#include "main/dll/dll_004B_cameramodeclimb.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0042_cameramodenormal.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "string.h"

extern f32 lbl_803E19A0;
extern f32 gCamClimbDistanceSmoothRate;
extern f32 gCamClimbTraceOrbitRadius;
extern f32 gCamClimbPi;
extern f32 gCamClimbHalfCircleBinaryAngle;
extern f32 gCamClimbTraceRadius;
extern f32 gCamClimbDegreesToBinaryAngle;
extern f32 gCamClimbDefaultEndMinHeight;
extern f32 gCamClimbDefaultEndMaxHeight;
extern f32 gCamClimbDefaultDistanceScale;
extern f32 gCamClimbDefaultHeightAdjustRate;

CameraModeClimbState* gCameraModeClimbState;

void CameraModeClimb_copyToCurrent(void) {
}

void CameraModeClimb_free(void) {
    mm_free(gCameraModeClimbState);
    gCameraModeClimbState = NULL;
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
    u8 traceWork[sizeof(CamcontrolTraceWork)];

    target = (GameObject*)camera->anim.targetObj;
    if (gCameraModeClimbState->transitionTimer != 0) {
        gCameraModeClimbState->transitionTimer -= framesThisStep;
        if (gCameraModeClimbState->transitionTimer < 0) {
            gCameraModeClimbState->transitionTimer = 0;
        }
        blend = (f32)(s32)(gCameraModeClimbState->transitionDuration - gCameraModeClimbState->transitionTimer) /
                (f32)(s32)gCameraModeClimbState->transitionDuration;
        gCameraModeClimbState->relativePosition = blend * (f32)(s32)(gCameraModeClimbState->targetRelativePosition -
                                                                     gCameraModeClimbState->startRelativePosition) +
                                                  (f32)(u32)gCameraModeClimbState->startRelativePosition;
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
        value = lbl_803E19A0;
    }
    value = value * (gCameraModeClimbState->heightAdjustRate * timeDelta);
    camera->anim.worldPosY = camera->anim.worldPosY + value;
    distance = gCameraModeClimbState->targetDistance;
    distance = distance - gCameraModeClimbState->smoothedDistance;
    distance = distance * (gCamClimbDistanceSmoothRate * timeDelta);
    gCameraModeClimbState->smoothedDistance = gCameraModeClimbState->smoothedDistance + distance;
    trigValue = mathSinf((gCamClimbPi * (f32)(s32)target->anim.rotX) / gCamClimbHalfCircleBinaryAngle);
    traceFrom[0] = gCamClimbTraceOrbitRadius * trigValue + target->anim.worldPosX;
    traceFrom[1] = target->anim.worldPosY;
    trigValue = mathCosf((gCamClimbPi * (f32)(s32)target->anim.rotX) / gCamClimbHalfCircleBinaryAngle);
    traceFrom[2] = gCamClimbTraceOrbitRadius * trigValue + target->anim.worldPosZ;
    trigValue = mathSinf((gCamClimbPi * (f32)(s32)target->anim.rotX) / gCamClimbHalfCircleBinaryAngle);
    camera->anim.worldPosX = gCameraModeClimbState->smoothedDistance * trigValue + traceFrom[0];
    trigValue = mathCosf((gCamClimbPi * (f32)(s32)target->anim.rotX) / gCamClimbHalfCircleBinaryAngle);
    camera->anim.worldPosZ = gCameraModeClimbState->smoothedDistance * trigValue + traceFrom[2];
    camcontrol_traceMove(traceFrom, &camera->anim.worldPosX, traceOut, (u8*)&traceWork, 3, 1, 1,
                         gCamClimbTraceRadius);
    camera->anim.worldPosX = traceOut[0];
    camera->anim.worldPosY = traceOut[1];
    camera->anim.worldPosZ = traceOut[2];
    (*gCameraInterface)
        ->getRelativePosition(camera, &relX, &value, &relZ, &distance,
                              (f32)(u32)(u16)gCameraModeClimbState->relativePosition, 0);
    {
        int targetYaw = 0x8000 - (u16)getAngle(relX, relZ);
        angleDelta = targetYaw - (u16)camera->anim.rotX;
    }
    if (angleDelta > 0x8000) {
        angleDelta = angleDelta - 0xffff;
    }
    if (angleDelta < -0x8000) {
        angleDelta = angleDelta + 0xffff;
    }
    camera->anim.rotX += angleDelta;
    value = camera->anim.worldPosY - (target->anim.worldPosY + (f32)(u32)(u16)gCameraModeClimbState->relativePosition);
    angle = getAngle(value, distance);
    angleDelta = angle & 0xffff;
    angleDelta -= (u16)camera->anim.rotY;
    if (angleDelta > 0x8000) {
        angleDelta = angleDelta - 0xffff;
    }
    if (angleDelta < -0x8000) {
        angleDelta = angleDelta + 0xffff;
    }
    camera->anim.rotY += (angleDelta * framesThisStep) / 6;
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
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
    int handler;

    if (gCameraModeClimbState == NULL) {
        gCameraModeClimbState = (CameraModeClimbState*)mmAlloc(sizeof(CameraModeClimbState), 0xf, 0);
    }
    switch (mode) {
    case 2:
        gCameraModeClimbState->startRelativePosition = gCameraModeClimbState->relativePosition;
        gCameraModeClimbState->startMinHeight = gCameraModeClimbState->minHeight;
        gCameraModeClimbState->startMaxHeight = gCameraModeClimbState->maxHeight;
        gCameraModeClimbState->startDistance = gCameraModeClimbState->targetDistance;
        gCameraModeClimbState->targetRelativePosition =
            (u16)(int)(gCamClimbDegreesToBinaryAngle * (f32)transition->relativePosition);
        gCameraModeClimbState->endMinHeight = transition->minHeight;
        gCameraModeClimbState->endMaxHeight = transition->maxHeight;
        gCameraModeClimbState->endDistance = transition->distance;
        gCameraModeClimbState->transitionTimer = (s16)transition->duration;
        gCameraModeClimbState->transitionDuration = (s16)transition->duration;
        break;
    case 1:
    default:
        memset(gCameraModeClimbState, 0, sizeof(CameraModeClimbState));
        handler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        (*(VtableFn*)(**(int**)(handler + 4) + 0x20))(&defaultDistB, &defaultDistA, &defaultMinHeight,
                                                      &defaultMaxHeight, &defaultRelPos);
        (*gCameraInterface)
            ->getRelativePosition(camera, &outX, &outY, &outZ, &defaultDistXZ,
                                  (f32)(u16)gCameraModeClimbState->relativePosition, 0);
        gCameraModeClimbState->startRelativePosition = defaultRelPos;
        gCameraModeClimbState->startMinHeight = defaultMinHeight;
        gCameraModeClimbState->startMaxHeight = defaultMaxHeight;
        gCameraModeClimbState->startDistance = defaultDistXZ;
        gCameraModeClimbState->targetRelativePosition = 30;
        gCameraModeClimbState->endMinHeight = gCamClimbDefaultEndMinHeight;
        gCameraModeClimbState->endMaxHeight = gCamClimbDefaultEndMaxHeight;
        gCameraModeClimbState->endDistance = gCamClimbDefaultDistanceScale * (defaultDistA + defaultDistB);
        gCameraModeClimbState->transitionTimer = 60;
        gCameraModeClimbState->transitionDuration = 60;
        gCameraModeClimbState->smoothedDistance = defaultDistXZ;
        gCameraModeClimbState->heightAdjustRate = gCamClimbDefaultHeightAdjustRate;
        break;
    }
}

void CameraModeClimb_release(void) {
}

void CameraModeClimb_initialise(void) {
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
