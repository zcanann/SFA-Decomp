/*
 * DLL 81 / 0x51 - cannon camera mode.
 */
#include "main/dll/dll_0051_cameramodecannon.h"

#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/mm.h"
#include "main/objprint_api.h"

CameraModeCannonState* gCameraModeCannonState;

void CameraModeCannon_copyToCurrent(void) {
}

void CameraModeCannon_free(void) {
    mm_free(gCameraModeCannonState);
    gCameraModeCannonState = NULL;
}

void CameraModeCannon_update(CameraObject* camera) {
    s16* modelRotation;
    s16 currentYaw;
    s16 yawDelta;

    modelRotation = objFindJointPoseVector(gCameraModeCannonState->target, 0);
    if (gCameraModeCannonState->target == NULL) {
        return;
    }
    currentYaw = camera->anim.rotX;
    yawDelta = (s16)((0x8000 - gCameraModeCannonState->target->anim.rotX) - modelRotation[1] - currentYaw);
    camera->anim.rotX = (f32)(s32)currentYaw + (f32)(s32)yawDelta / 5.0f;
    camera->anim.localPosX = gCameraModeCannonState->target->anim.localPosX -
                             60.0f * mathSinf(3.1415927f * (f32)(s32)(-camera->anim.rotX) / 32768.0f);
    camera->anim.localPosY = 80.0f + gCameraModeCannonState->target->anim.localPosY;
    camera->anim.localPosZ = gCameraModeCannonState->target->anim.localPosZ -
                             60.0f * mathCosf(3.1415927f * (f32)(s32)(-camera->anim.rotX) / 32768.0f);
}

void CameraModeCannon_init(CameraObject* camera, int unused, CameraModeCannonInitParams* params) {
    if (gCameraModeCannonState == NULL) {
        gCameraModeCannonState = (CameraModeCannonState*)mmAlloc(sizeof(CameraModeCannonState), 15, 0);
    }
    if (params != NULL) {
        gCameraModeCannonState->target = params->target;
    } else {
        gCameraModeCannonState->target = NULL;
    }
    camera->anim.rotY = 2800;
}

void CameraModeCannon_release(void) {
}

void CameraModeCannon_initialise(void) {
}

CameraModeCannonDescriptor gCameraModeCannonDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeCannon_initialise,
    CameraModeCannon_release,
    NULL,
    CameraModeCannon_init,
    CameraModeCannon_update,
    CameraModeCannon_free,
    CameraModeCannon_copyToCurrent,
    NULL,
};
