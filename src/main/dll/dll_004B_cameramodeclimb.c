/*
 * cameramodeclimb (DLL 0x4B) - camera mode used while the player is
 * climbing. Owns a single heap-allocated CameraModeClimbState
 * (lbl_803DD578).
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
extern f32 lbl_803E19A4;
extern f32 lbl_803E19A8;
extern f32 lbl_803E19AC;
extern f32 lbl_803E19B0;
extern f32 lbl_803E19B4;
extern f32 lbl_803E19B8;
extern f32 lbl_803E19BC;
extern f32 lbl_803E19C0;
extern f32 lbl_803E19C4;
extern f32 lbl_803E19C8;

extern CameraModeClimbState* lbl_803DD578;




extern u8 framesThisStep;
extern f32 timeDelta;

void CameraModeClimb_copyToCurrent_nop(void)
{
}

void CameraModeClimb_free(void)
{
    mm_free(lbl_803DD578);
    lbl_803DD578 = NULL;
}

void CameraModeClimb_update(CameraObject* camObj)
{
    f32 blend;
    f32 targetY;
    f32 hi;
    f32 lo;
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
    if (lbl_803DD578->transitionTimer != 0)
    {
        lbl_803DD578->transitionTimer -= framesThisStep;
        if (lbl_803DD578->transitionTimer < 0)
        {
            lbl_803DD578->transitionTimer = 0;
        }
        blend = (f32)(s32)(lbl_803DD578->transitionDuration - lbl_803DD578->transitionTimer) /
                (f32)(s32)lbl_803DD578->transitionDuration;
        lbl_803DD578->relativePosition =
            blend * (f32)(s32)(lbl_803DD578->targetRelativePosition - lbl_803DD578->startRelativePosition) +
            (f32)(u32)(u16)lbl_803DD578->startRelativePosition;
        lbl_803DD578->targetDistance =
            blend * (lbl_803DD578->endDistance - lbl_803DD578->startDistance) + lbl_803DD578->startDistance;
        lbl_803DD578->minHeight =
            blend * (lbl_803DD578->endMinHeight - lbl_803DD578->startMinHeight) + lbl_803DD578->startMinHeight;
        lbl_803DD578->maxHeight =
            blend * (lbl_803DD578->endMaxHeight - lbl_803DD578->startMaxHeight) + lbl_803DD578->startMaxHeight;
    }
    targetY = viewObj->anim.worldPosY;
    hi = targetY + lbl_803DD578->maxHeight;
    lo = targetY + lbl_803DD578->minHeight;
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
    clamped = clamped * (lbl_803DD578->heightAdjustRate * timeDelta);
    camObj->anim.worldPosY = camObj->anim.worldPosY + clamped;
    dist = lbl_803DD578->targetDistance;
    dist = dist - lbl_803DD578->smoothedDistance;
    dist = dist * (lbl_803E19A4 * timeDelta);
    lbl_803DD578->smoothedDistance = lbl_803DD578->smoothedDistance + dist;
    trigValue = mathSinf((lbl_803E19AC * (f32)(s32)viewObj->anim.rotX) / lbl_803E19B0);
    traceFrom[0] = lbl_803E19A8 * trigValue + viewObj->anim.worldPosX;
    traceFrom[1] = viewObj->anim.worldPosY;
    trigValue = mathCosf((lbl_803E19AC * (f32)(s32)viewObj->anim.rotX) / lbl_803E19B0);
    traceFrom[2] = lbl_803E19A8 * trigValue + viewObj->anim.worldPosZ;
    trigValue = mathSinf((lbl_803E19AC * (f32)(s32)viewObj->anim.rotX) / lbl_803E19B0);
    camObj->anim.worldPosX = lbl_803DD578->smoothedDistance * trigValue + traceFrom[0];
    trigValue = mathCosf((lbl_803E19AC * (f32)(s32)viewObj->anim.rotX) / lbl_803E19B0);
    camObj->anim.worldPosZ = lbl_803DD578->smoothedDistance * trigValue + traceFrom[2];
    camcontrol_traceMove(traceFrom, &camObj->anim.worldPosX, traceOut, traceWork, 3, 1, 1, lbl_803E19B4);
    camObj->anim.worldPosX = traceOut[0];
    camObj->anim.worldPosY = traceOut[1];
    camObj->anim.worldPosZ = traceOut[2];
    (*gCameraInterface)->getRelativePosition((f32)(u32)(u16)lbl_803DD578->relativePosition,
                                             (int)camObj, &relX, &clamped,
                                             &relZ, &dist, 0);
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
              (viewObj->anim.worldPosY + (f32)(u32)(u16)lbl_803DD578->relativePosition);
    yawDelta = (u16)getAngle(clamped, dist) - (u16)camObj->anim.rotY;
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

    if (lbl_803DD578 == NULL)
    {
        lbl_803DD578 = (CameraModeClimbState*)mmAlloc(sizeof(CameraModeClimbState), 0xf, 0);
    }
    switch (mode)
    {
    case 2:
        lbl_803DD578->startRelativePosition = lbl_803DD578->relativePosition;
        lbl_803DD578->startMinHeight = lbl_803DD578->minHeight;
        lbl_803DD578->startMaxHeight = lbl_803DD578->maxHeight;
        lbl_803DD578->startDistance = lbl_803DD578->targetDistance;
        lbl_803DD578->targetRelativePosition = (u16)(int)(lbl_803E19B8 * (f32)(s8)args[3]);
        lbl_803DD578->endMinHeight = (f32)(s8)args[5];
        lbl_803DD578->endMaxHeight = (f32)(s8)args[4];
        lbl_803DD578->endDistance = (f32)(s8)args[2];
        lbl_803DD578->transitionTimer = (s16)(s8)args[1];
        lbl_803DD578->transitionDuration = (s16)(s8)args[1];
        break;
    case 1:
    default:
        memset(lbl_803DD578, 0, sizeof(CameraModeClimbState));
        handler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        (*(VtableFn*)(**(int**)(handler + 4) + 0x20))(&defaultDistB, &defaultDistA, &defaultMinHeight,
                                                  &defaultMaxHeight, &defaultRelPos);
        (*gCameraInterface)->getRelativePosition((f32)(u16)lbl_803DD578->relativePosition,
                                                 arg1, &outX, &outY, &outZ, &defaultDistXZ, 0);
        lbl_803DD578->startRelativePosition = defaultRelPos;
        lbl_803DD578->startMinHeight = defaultMinHeight;
        lbl_803DD578->startMaxHeight = defaultMaxHeight;
        lbl_803DD578->startDistance = defaultDistXZ;
        lbl_803DD578->targetRelativePosition = 30;
        lbl_803DD578->endMinHeight = lbl_803E19BC;
        lbl_803DD578->endMaxHeight = lbl_803E19C0;
        lbl_803DD578->endDistance = lbl_803E19C4 * (defaultDistA + defaultDistB);
        lbl_803DD578->transitionTimer = 60;
        lbl_803DD578->transitionDuration = 60;
        lbl_803DD578->smoothedDistance = defaultDistXZ;
        lbl_803DD578->heightAdjustRate = lbl_803E19C8;
        break;
    }
}

void CameraModeClimb_release(void)
{
}

void CameraModeClimb_initialise(void)
{
}
