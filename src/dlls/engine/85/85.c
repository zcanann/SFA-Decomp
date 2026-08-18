/*
 * DLL 85 / 0x55 - unnamed low-angle camera mode.
 */
#include "main/dll/dll_0055_cameramode.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/frame_timing.h"
#include "main/mm.h"

CameraMode55State* gCameraMode55State;

void CameraMode55_copyToCurrent(void) {
}

void CameraMode55_free(void) {
    mm_free(gCameraMode55State);
    gCameraMode55State = NULL;
}

void CameraMode55_update(CameraObject* camera) {
    GameObject* target = camera->anim.targetObj;

    gCameraMode55State->timer -= 0.2f * timeDelta;
    if (gCameraMode55State->timer < 20.0f) {
        gCameraMode55State->timer = 20.0f;
    }
    camera->anim.localPosX =
        target->anim.worldPosX - 5.0f * mathSinf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
    camera->anim.localPosY = gCameraMode55State->cameraY;
    camera->anim.localPosZ =
        target->anim.worldPosZ - 5.0f * mathCosf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
    camera->anim.rotX = 0;
    camera->anim.rotY = -0x4000;
    camera->anim.rotZ = 0;
}

void CameraMode55_init(CameraObject* camera) {
    if (gCameraMode55State == NULL) {
        gCameraMode55State = (CameraMode55State*)mmAlloc(sizeof(CameraMode55State), 15, 0);
    }
    gCameraMode55State->timer = 100.0f;
    gCameraMode55State->cameraY = ((GameObject*)camera->anim.targetObj)->anim.worldPosY - 200.0f;
}

void CameraMode55_release(void) {
}

void CameraMode55_initialise(void) {
}

CameraMode55Descriptor gCameraMode55Descriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraMode55_initialise,
    CameraMode55_release,
    NULL,
    CameraMode55_init,
    CameraMode55_update,
    CameraMode55_free,
    CameraMode55_copyToCurrent,
    NULL,
};
