/*
 * DLL 69 / 0x45 - talk camera mode.
 */
#include "main/dll/CAM/dll_0045_camTalk.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/camera_interface.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "string.h"

int lbl_803DD544;
CameraModeTalkState* gCameraModeTalkState;

void CameraModeTalk_copyToCurrent(const CameraModeTalkInputs* inputs) {
    gCameraModeTalkState->turnInput = inputs->turn;
    gCameraModeTalkState->heightInput = inputs->height;
    gCameraModeTalkState->rollInput = inputs->roll;
    gCameraModeTalkState->pitchTarget = inputs->pitch;
}

void CameraModeTalk_free(void) {
    mm_free(gCameraModeTalkState);
    gCameraModeTalkState = NULL;
}

static void CameraModeTalk_resetSmoothing(CameraModeTalkState* state) {
    state->smoothedYawOffset = 0.0f;
}

void CameraModeTalk_update(CameraObject* camera) {
    int targetAngle;
    f32 followDist;
    f32 heightT;
    f32 followTermB;
    f32 followTermA;
    f32 yawSmoothing;
    f32 yawTarget;
    s16 angleDelta;
    u16 cameraAngle;
    GameObject* target;
    CameraModeTalkState* state;
    f32 sinYaw;
    f32 cosYaw;
    f32 sinPitch;
    f32 cosPitch;
    f32 pivotX;
    f32 pivotY;
    f32 pivotZ;
    MatrixTransform targetTransform;
    f32 matrix[16];

    (*gCameraInterface)->getDefaultHandlerEntry();
    target = (GameObject*)camera->anim.targetObj;
    if (target != NULL) {
        camera->fov = 85.0f;
        targetTransform.x = target->anim.worldPosX;
        targetTransform.y = target->anim.worldPosY;
        targetTransform.z = target->anim.worldPosZ;
        targetTransform.scale = 1.0f;
        targetTransform.rotX = target->anim.rotX;
        targetTransform.rotY = gCameraModeTalkState->pitchTarget;
        targetTransform.rotZ = 0;
        setMatrixFromObjectPos(matrix, &targetTransform);
        Matrix_TransformPoint(matrix, 0.0f, 20.0f, 0.0f, &pivotX, &pivotY, &pivotZ);
        angleDelta = 0x8000 - target->anim.rotX;
        camera->anim.rotX = angleDelta;
        state = gCameraModeTalkState;
        yawSmoothing = 0.1f;
        yawTarget = 12.0f * state->turnInput;
        state->smoothedYawOffset += yawSmoothing * (yawTarget - state->smoothedYawOffset);
        camera->anim.rotX = camera->anim.rotX + gCameraModeTalkState->smoothedYawOffset;
        targetAngle = 3072.0f - gCameraModeTalkState->pitchTarget;
        cameraAngle = camera->anim.rotY;
        angleDelta = targetAngle - cameraAngle;
        if (angleDelta > 0x8000) {
            angleDelta = angleDelta - 0xFFFF;
        }
        if (angleDelta < -0x8000) {
            angleDelta = angleDelta + 0xFFFF;
        }
        camera->anim.rotY += (angleDelta >> 3);
        sinYaw = mathSinf(3.14159274f * (camera->anim.rotX - 0x4000) / 32768.0f);
        cosYaw = mathCosf(3.14159274f * (camera->anim.rotX - 0x4000) / 32768.0f);
        cosPitch = mathCosf(3.14159274f * camera->anim.rotY / 32768.0f);
        sinPitch = mathSinf(3.14159274f * camera->anim.rotY / 32768.0f);
        state = gCameraModeTalkState;
        heightT = -state->heightInput / 6.0f;
        followTermA = 0.2f;
        state->followDistance +=
            followTermA * ((50.0f + 25.0f * ((heightT < 0.0f) ? 0.0f : ((heightT > 1.0f) ? 1.0f : heightT))) -
                           state->followDistance);
        followDist = gCameraModeTalkState->followDistance;
        followTermA = followDist * sinPitch;
        followTermB = followDist * cosPitch;
        cosYaw = followTermB * cosYaw;
        followTermB = followTermB * sinYaw;
        camera->anim.worldPosX = pivotX + cosYaw;
        camera->anim.worldPosY = pivotY + followTermA;
        camera->anim.worldPosZ = pivotZ + followTermB;
        targetAngle = 0.2f * gCameraModeTalkState->rollInput;
        cameraAngle = camera->anim.rotZ;
        angleDelta = targetAngle - cameraAngle;
        if (angleDelta > 0x8000) {
            angleDelta = angleDelta - 0xFFFF;
        }
        if (angleDelta < -0x8000) {
            angleDelta = angleDelta + 0xFFFF;
        }
        camera->anim.rotZ += (angleDelta * timeDelta) / 16.0f;
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       (GameObject*)camera->anim.parent);
    }
}

void CameraModeTalk_init(CameraObject* camera) {
    if (gCameraModeTalkState == NULL) {
        gCameraModeTalkState = (CameraModeTalkState*)mmAlloc(sizeof(CameraModeTalkState), 0xF, 0);
    }
    memset(gCameraModeTalkState, 0, sizeof(CameraModeTalkState));
    gCameraModeTalkState->entryFov = camera->fov;
    gCameraModeTalkState->defaultFov = 85.0f;
    gCameraModeTalkState->defaultScale = 1.0f;
    gCameraModeTalkState->followDistance = 50.0f;
}

void CameraModeTalk_release(void) {
}

void CameraModeTalk_initialise(void) {
}

CameraModeTalkDescriptor gCameraModeTalkDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeTalk_initialise,
    CameraModeTalk_release,
    NULL,
    CameraModeTalk_init,
    CameraModeTalk_update,
    CameraModeTalk_free,
    CameraModeTalk_copyToCurrent,
    NULL,
};
