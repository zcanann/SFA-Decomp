#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_B8.h"

extern CameraViewSlot* Camera_GetCurrentViewSlot(void);
extern float Camera_GetFovY(void);

void firstPersonZoomOutOnExit(u8 blendFrames, u8 blendFlags)
{
    CameraViewSlot* vs;

    float fov_const;

    Camera_GetCurrentViewSlot();
    fov_const = gCamcontrolNormalizedMax;
    CAMCONTROL_CAMERA->blendProgress = fov_const;
    CAMCONTROL_CAMERA->blendStep = fov_const / (float)blendFrames;
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
