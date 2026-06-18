/*
 * dll_b8 - camcontrol blend helpers (companion to the CAM/camcontrol DLL).
 *
 * Seeds the camera-blend state used to interpolate from one camera setup to
 * another: firstPersonZoomOutOnExit captures the current view slot (position,
 * yaw/pitch/roll) and FOV as the blend start, sets the full blend progress and
 * per-frame step over blendFrames, and records the requested blend-axis flags
 * (called when leaving first-person/viewfinder). cameraSetInterpMode selects
 * the blend curve used while interpolating.
 */
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_B8.h"

extern CameraViewSlot* Camera_GetCurrentViewSlot(void);
extern f32 Camera_GetFovY(void);

void firstPersonZoomOutOnExit(u8 blendFrames, u8 blendFlags)
{
    CameraViewSlot* vs;
    f32 blendProgress;

    Camera_GetCurrentViewSlot();
    blendProgress = gCamcontrolNormalizedMax;
    CAMCONTROL_CAMERA->blendProgress = blendProgress;
    CAMCONTROL_CAMERA->blendStep = blendProgress / (float)blendFrames;
    CAMCONTROL_CAMERA->queuedBlendFlags = blendFlags;

    vs = Camera_GetCurrentViewSlot();
    CAMCONTROL_CAMERA->blendStartX = vs->x;
    CAMCONTROL_CAMERA->blendStartY = vs->y;
    CAMCONTROL_CAMERA->blendStartZ = vs->z;
    CAMCONTROL_CAMERA->blendStartYaw = vs->yaw;
    CAMCONTROL_CAMERA->blendStartPitch = vs->pitch;
    CAMCONTROL_CAMERA->blendStartRoll = vs->roll;

    CAMCONTROL_CAMERA->blendStartFovY = Camera_GetFovY();
}

void cameraSetInterpMode(u8 mode) { CAMCONTROL_CAMERA->blendCurveMode = mode; }
