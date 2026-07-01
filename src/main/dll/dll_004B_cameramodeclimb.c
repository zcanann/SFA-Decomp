/*
 * cameramodeclimb (DLL 0x4B) - camera mode used while the player is
 * climbing. Owns a single heap-allocated CameraModeClimbState
 * (gCamClimbState).
 *
 * _init(mode) seeds that state: mode 2 reads a 6-byte arg block
 * (duration, distance, min/max height, relative-position angle) and
 * sets up a transition FROM the live values TO those targets; mode 1
 * (and any other) zeroes the state and primes a 60-step default
 * transition by sampling the active camera handler's defaults.
 *
 * _update(camObj) ticks the transition timer (lerping distance, min/max
 * height and relative position toward their targets), drives the camera
 * height toward the view target's clamped height band, smooths the
 * follow distance, orbits the camera around the view target by the
 * relative-position angle, traces the move against geometry, then yaws
 * camObj toward the target and converts the world point into the
 * camera's local frame.
 */
#include "main/dll/CAM/camclimb_state.h"
#include "main/dll/CAM/cutCam.h"
#include "main/mm.h"
#include "main/camera_interface.h"
#include "main/object_transform.h"
#include "main/dll/dll_80220608_shared.h"
extern void memset(void* dst, int val, int size);
extern f32 lbl_803E19A0;
extern f32 gCamClimbDistanceSmoothRate;
extern f32 gCamClimbTraceOrbitRadius;
extern f32 gCamClimbPi;
extern f32 gCamClimbHalfCircleBinaryAngle;
extern f32 lbl_803E19B4;
extern f32 gCamClimbDegreesToBinaryAngle;
extern f32 gCamClimbDefaultEndMinHeight;
extern f32 gCamClimbDefaultEndMaxHeight;
extern f32 lbl_803E19C4;
extern f32 gCamClimbDefaultHeightAdjustRate;
extern CameraModeClimbState* gCamClimbState;

void CameraModeClimb_copyToCurrent_nop(void)
{
}

void CameraModeClimb_free(void)
{
    mm_free(gCamClimbState);
    gCamClimbState = NULL;
}

void CameraModeClimb_update(CameraObject* camObj)
{
    f32 blend;
    f32 targetY;
    f32 hi;
    f32 lo;
    u32 angle;
    int yawDelta;
    GameObject* viewObj;
    f32 trigValue;
    f32 relX;
    f32 clamped;
    f32 relZ;
    f32 dist;
    f32 traceFrom[3];
    f32 traceOut[3];
    u8 traceWork[CAMCONTROL_TRACE_WORK_SIZE];

    viewObj = (GameObject*)camObj->anim.targetObj;
    if (gCamClimbState->transitionTimer != 0)
    {
        gCamClimbState->transitionTimer -= framesThisStep;
        if (gCamClimbState->transitionTimer < 0)
        {
            gCamClimbState->transitionTimer = 0;
        }
        blend = (f32)(s32)(gCamClimbState->transitionDuration - gCamClimbState->transitionTimer) /
                (f32)(s32)gCamClimbState->transitionDuration;
        gCamClimbState->relativePosition =
            blend * (f32)(s32)(gCamClimbState->targetRelativePosition - gCamClimbState->startRelativePosition) +
            (f32)(u32)(u16)gCamClimbState->startRelativePosition;
        gCamClimbState->targetDistance =
            blend * (gCamClimbState->endDistance - gCamClimbState->startDistance) + gCamClimbState->startDistance;
        gCamClimbState->minHeight =
            blend * (gCamClimbState->endMinHeight - gCamClimbState->startMinHeight) + gCamClimbState->startMinHeight;
        gCamClimbState->maxHeight =
            blend * (gCamClimbState->endMaxHeight - gCamClimbState->startMaxHeight) + gCamClimbState->startMaxHeight;
    }
    targetY = viewObj->anim.worldPosY;
    hi = targetY + gCamClimbState->maxHeight;
    lo = targetY + gCamClimbState->minHeight;
    blend = camObj->anim.worldPosY;
    if (blend < lo)
    {
        clamped = lo - blend;
    }
    else if (blend > hi)
    {
        clamped = hi - blend;
    }
    else
    {
        clamped = lbl_803E19A0;
    }
    clamped = clamped * (gCamClimbState->heightAdjustRate * timeDelta);
    camObj->anim.worldPosY = camObj->anim.worldPosY + clamped;
    dist = gCamClimbState->targetDistance;
    dist = dist - gCamClimbState->smoothedDistance;
    dist = dist * (gCamClimbDistanceSmoothRate * timeDelta);
    gCamClimbState->smoothedDistance = gCamClimbState->smoothedDistance + dist;
    trigValue = mathSinf((gCamClimbPi * (f32)(s32)viewObj->anim.rotX) / gCamClimbHalfCircleBinaryAngle);
    traceFrom[0] = gCamClimbTraceOrbitRadius * trigValue + viewObj->anim.worldPosX;
    traceFrom[1] = viewObj->anim.worldPosY;
    trigValue = mathCosf((gCamClimbPi * (f32)(s32)viewObj->anim.rotX) / gCamClimbHalfCircleBinaryAngle);
    traceFrom[2] = gCamClimbTraceOrbitRadius * trigValue + viewObj->anim.worldPosZ;
    trigValue = mathSinf((gCamClimbPi * (f32)(s32)viewObj->anim.rotX) / gCamClimbHalfCircleBinaryAngle);
    camObj->anim.worldPosX = gCamClimbState->smoothedDistance * trigValue + traceFrom[0];
    trigValue = mathCosf((gCamClimbPi * (f32)(s32)viewObj->anim.rotX) / gCamClimbHalfCircleBinaryAngle);
    camObj->anim.worldPosZ = gCamClimbState->smoothedDistance * trigValue + traceFrom[2];
    camcontrol_traceMove(traceFrom, &camObj->anim.worldPosX, traceOut, traceWork, 3, 1, 1, lbl_803E19B4);
    camObj->anim.worldPosX = traceOut[0];
    camObj->anim.worldPosY = traceOut[1];
    camObj->anim.worldPosZ = traceOut[2];
    ((void (*)(int, f32*, f32*, f32*, f32*, f32, int))(*gCameraInterface)->getRelativePosition)(
        (int)camObj, &relX, &clamped, &relZ, &dist,
        (f32)(u32)(u16)gCamClimbState->relativePosition, 0);
    {
        int t = 0x8000 - (u16)getAngle(relX, relZ);
        yawDelta = t - (u16)camObj->anim.rotX;
    }
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta - 0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    camObj->anim.rotX += yawDelta;
    clamped = camObj->anim.worldPosY -
              (viewObj->anim.worldPosY + (f32)(u32)(u16)gCamClimbState->relativePosition);
    angle = getAngle(clamped, dist);
    yawDelta = angle & 0xffff;
    yawDelta -= (u16)camObj->anim.rotY;
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta - 0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    camObj->anim.rotY += (yawDelta * framesThisStep) / 6;
    Obj_TransformWorldPointToLocal(camObj->anim.worldPosX, camObj->anim.worldPosY,
                                   camObj->anim.worldPosZ, &camObj->anim.localPosX,
                                   &camObj->anim.localPosY, &camObj->anim.localPosZ,
                                   *(int*)&camObj->anim.parent);
}

void CameraModeClimb_init(int arg1, int mode, s8* args)
{
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

    if (gCamClimbState == NULL)
    {
        gCamClimbState = (CameraModeClimbState*)mmAlloc(sizeof(CameraModeClimbState), 0xf, 0);
    }
    switch (mode)
    {
    case 2:
        gCamClimbState->startRelativePosition = gCamClimbState->relativePosition;
        gCamClimbState->startMinHeight = gCamClimbState->minHeight;
        gCamClimbState->startMaxHeight = gCamClimbState->maxHeight;
        gCamClimbState->startDistance = gCamClimbState->targetDistance;
        gCamClimbState->targetRelativePosition = (u16)(int)(gCamClimbDegreesToBinaryAngle * (f32)(s8)args[3]);
        gCamClimbState->endMinHeight = (f32)(s8)args[5];
        gCamClimbState->endMaxHeight = (f32)(s8)args[4];
        gCamClimbState->endDistance = (f32)(s8)args[2];
        gCamClimbState->transitionTimer = (s16)(s8)args[1];
        gCamClimbState->transitionDuration = (s16)(s8)args[1];
        break;
    case 1:
    default:
        memset(gCamClimbState, 0, sizeof(CameraModeClimbState));
        handler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        (*(VtableFn*)(**(int**)(handler + 4) + 0x20))(&defaultDistB, &defaultDistA, &defaultMinHeight,
                                                  &defaultMaxHeight, &defaultRelPos);
        ((void (*)(int, f32*, f32*, f32*, f32*, f32, int))(*gCameraInterface)->getRelativePosition)(
            arg1, &outX, &outY, &outZ, &defaultDistXZ, (f32)(u16)gCamClimbState->relativePosition, 0);
        gCamClimbState->startRelativePosition = defaultRelPos;
        gCamClimbState->startMinHeight = defaultMinHeight;
        gCamClimbState->startMaxHeight = defaultMaxHeight;
        gCamClimbState->startDistance = defaultDistXZ;
        gCamClimbState->targetRelativePosition = 30;
        gCamClimbState->endMinHeight = gCamClimbDefaultEndMinHeight;
        gCamClimbState->endMaxHeight = gCamClimbDefaultEndMaxHeight;
        gCamClimbState->endDistance = lbl_803E19C4 * (defaultDistA + defaultDistB);
        gCamClimbState->transitionTimer = 60;
        gCamClimbState->transitionDuration = 60;
        gCamClimbState->smoothedDistance = defaultDistXZ;
        gCamClimbState->heightAdjustRate = gCamClimbDefaultHeightAdjustRate;
        break;
    }
}

void CameraModeClimb_release(void)
{
}

void CameraModeClimb_initialise(void)
{
}
