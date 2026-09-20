/*
 * DLL 79 / 0x4F.
 */
#include "main/dll/dll_004F_cameramode.h"

#include "MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "game/objects/object.h"
#include "main/curve.h"
#include "main/frame_timing.h"
#include "main/mm.h"

CameraMode4FState* gCameraMode4FState;

void CameraMode4F_copyToCurrent(void) {
}

void CameraMode4F_free(void) {
    mm_free(gCameraMode4FState);
    gCameraMode4FState = NULL;
}

void CameraMode4F_update(CameraObject* camera) {
    GameObject* target;
    f32 blendCurve[4];
    f32 blendValue;
    f32 cosValue;
    f32 sinValue;
    s16 yaw;

    blendCurve[0] = 0.0f;
    blendCurve[1] = 1.0f;
    blendCurve[2] = 0.0f;
    blendCurve[3] = 0.0f;
    blendValue = Curve_EvalHermite(blendCurve, gCameraMode4FState->blendProgress, NULL);
    yaw = (s16)(0x8000 - ((GameObject*)camera->anim.targetObj)->anim.rotX);
    yaw += (s32)(14560.0f * blendValue);
    target = (GameObject*)camera->anim.targetObj;
    {
        f32 radians = (3.1415927f * (f32)(s32)yaw) / 32768.0f;
        cosValue = mathCosf(radians);
        sinValue = mathSinf(radians);
    }
    camera->anim.localPosX = target->anim.worldPosX + (20.0f * cosValue - -10.0f * sinValue);
    camera->anim.localPosZ = target->anim.worldPosZ + (20.0f * sinValue + -10.0f * cosValue);
    camera->anim.localPosY = (35.0f + target->anim.worldPosY) - 15.0f * blendValue;
    camera->anim.rotY = (s16)(0x11c6 - (s32)(35.0f * (182.0f * blendValue)));
    camera->anim.rotX = (s16)(yaw + 0x1ffe);
    camera->anim.rotZ = 0;
    camera->letterboxTargetOffset = 0;
    camera->fov = 60.0f;
    gCameraMode4FState->blendProgress += 0.005f * timeDelta;
    if (gCameraMode4FState->blendProgress > 1.0f) {
        gCameraMode4FState->blendProgress = 1.0f;
    }
}

void CameraMode4F_init(void) {
    if (gCameraMode4FState == NULL) {
        gCameraMode4FState = (CameraMode4FState*)mmAlloc(sizeof(CameraMode4FState), 15, 0);
    }
    gCameraMode4FState->blendProgress = 0.0f;
}

void CameraMode4F_release(void) {
}

void CameraMode4F_initialise(void) {
}

CameraMode4FDescriptor gCameraMode4FDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraMode4F_initialise,
    CameraMode4F_release,
    NULL,
    CameraMode4F_init,
    CameraMode4F_update,
    CameraMode4F_free,
    CameraMode4F_copyToCurrent,
    NULL,
};
