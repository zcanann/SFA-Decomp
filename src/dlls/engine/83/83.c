/*
 * DLL 83 / 0x53 - CloudRunner camera mode.
 */
#include "main/dll/dll_0053_cameramodecloudrunner.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/dll/DR/dll_0258_drcloudrunner.h"
#include "main/dll/player_api.h"
#include "main/dll/player_motion.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/vecmath.h"

CameraModeCloudRunnerState* gCameraModeCloudRunnerState;

f32 gCameraModeCloudRunnerTargetHeightOffset = 15.0f;
int gCameraModeCloudRunnerRollScale = -4;

void CameraModeCloudRunner_copyToCurrent(void) {
}

void CameraModeCloudRunner_free(void) {
    mm_free(gCameraModeCloudRunnerState);
    gCameraModeCloudRunnerState = NULL;
}

void CameraModeCloudRunner_update(CameraObject* camera) {
    GameObject* target = (GameObject*)camera->anim.targetObj;
    GameObject* focus;
    s16 targetYaw;
    s16 targetPitch;
    f32 focusX;
    f32 focusY;
    f32 focusZ;
    f32 yawX;
    f32 yawZ;
    f32 pitchHorizontalScale;
    f32 pitchVerticalScale;
    f32 radius;
    f32 xOffset;
    f32 yOffset;
    f32 horizontalRadius;
    MatrixTransform focusTransform;
    f32 focusMatrix[16];

    Player_GetAimAngles(target, &targetYaw, &targetPitch);
    focus = playerGetFocusObject(target);
    if (focus != NULL) {
        if (focus->anim.romDefNo == DR_CLOUDRUNNER_OBJECT_ID) {
            focusTransform.x = focus->anim.worldPosX;
            focusTransform.y = focus->anim.worldPosY;
            focusTransform.z = focus->anim.worldPosZ;
            focusTransform.rotX = focus->anim.rotX;
            focusTransform.rotY = focus->anim.rotY;
            focusTransform.rotZ = focus->anim.rotZ;
            focusTransform.scale = 1.0f;
            setMatrixFromObjectPos(focusMatrix, &focusTransform);
            Matrix_TransformPoint(focusMatrix, 0.0f, 65.0f, -10.0f, &focusX, &focusY, &focusZ);
        } else {
            focusX = target->anim.worldPosX;
            focusY = target->anim.worldPosY + gCameraModeCloudRunnerTargetHeightOffset;
            focusZ = target->anim.worldPosZ;
        }
    } else {
        focusX = target->anim.worldPosX;
        focusY = target->anim.worldPosY + gCameraModeCloudRunnerTargetHeightOffset;
        focusZ = target->anim.worldPosZ;
    }

    targetYaw = (s16)((0x8000 - target->anim.rotX) + targetYaw);
    targetYaw = (s16)(targetYaw - (u16)camera->anim.rotX);
    if (targetYaw > 0x8000) {
        targetYaw = targetYaw - 0xffff;
    }
    if (targetYaw < -0x8000) {
        targetYaw = targetYaw + 0xffff;
    }
    camera->anim.rotX += targetYaw;

    targetPitch = (s16)(targetPitch - (u16)camera->anim.rotY);
    if (targetPitch > 0x8000) {
        targetPitch = targetPitch - 0xffff;
    }
    if (targetPitch < -0x8000) {
        targetPitch = targetPitch + 0xffff;
    }
    camera->anim.rotY += targetPitch;

    camera->anim.rotZ = (s16)(target->anim.rotZ * gCameraModeCloudRunnerRollScale);

    yawX = mathSinf(3.1415927f * (f32)(s32)(camera->anim.rotX - 0x4000) / 32768.0f);
    yawZ = mathCosf(3.1415927f * (f32)(s32)(camera->anim.rotX - 0x4000) / 32768.0f);
    pitchHorizontalScale = mathCosf(3.1415927f * (f32)(s32)camera->anim.rotY / 32768.0f);
    pitchVerticalScale = mathSinf(3.1415927f * (f32)(s32)camera->anim.rotY / 32768.0f);
    radius = gCameraModeCloudRunnerState->radius;
    yOffset = radius * pitchVerticalScale;
    horizontalRadius = radius * pitchHorizontalScale;
    xOffset = horizontalRadius * yawZ;
    horizontalRadius = horizontalRadius * yawX;
    camera->anim.worldPosX = focusX + xOffset;
    camera->anim.worldPosY = focusY + yOffset;
    camera->anim.worldPosZ = focusZ + horizontalRadius;
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

void CameraModeCloudRunner_init(CameraObject* camera, int fallbackRadius, CameraModeCloudRunnerInitParams* params) {
    GameObject* targetObj = camera->anim.targetObj;

    if (gCameraModeCloudRunnerState == NULL) {
        gCameraModeCloudRunnerState = (CameraModeCloudRunnerState*)mmAlloc(sizeof(CameraModeCloudRunnerState), 15, 0);
    }
    {
        f32 computedRadius;
        if (params != NULL) {
            gCameraModeCloudRunnerState->focusX = params->focusX;
            gCameraModeCloudRunnerState->focusY = params->focusY;
            gCameraModeCloudRunnerState->focusZ = params->focusZ;
            computedRadius = params->radius;
        } else {
            gCameraModeCloudRunnerState->focusX = targetObj->anim.worldPosX;
            gCameraModeCloudRunnerState->focusY = targetObj->anim.worldPosY;
            gCameraModeCloudRunnerState->focusZ = targetObj->anim.worldPosZ;
            computedRadius = fallbackRadius;
        }
        gCameraModeCloudRunnerState->radius = computedRadius;
    }
    getAngle(camera->anim.worldPosX - gCameraModeCloudRunnerState->focusX,
             camera->anim.worldPosZ - gCameraModeCloudRunnerState->focusZ);
    {
        GameObject* target = (GameObject*)camera->anim.targetObj;
        f32* state = (f32*)gCameraModeCloudRunnerState;
        getAngle(target->anim.worldPosX - state[0], target->anim.worldPosZ - state[2]);
    }
}

void CameraModeCloudRunner_release(void) {
}

void CameraModeCloudRunner_initialise(void) {
}

CameraModeCloudRunnerDescriptor gCameraModeCloudRunnerDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeCloudRunner_initialise,
    CameraModeCloudRunner_release,
    NULL,
    CameraModeCloudRunner_init,
    CameraModeCloudRunner_update,
    CameraModeCloudRunner_free,
    CameraModeCloudRunner_copyToCurrent,
    NULL,
};
