/*
 * DLL 86 / 0x56 - Arwing camera mode.
 */
#include "main/dll/dll_0056_cameramodearwing.h"

#include "dolphin/mtx/vec.h"
#include "main/camera_interface.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/frame_timing.h"
#include "main/object_transform.h"
#include "main/vecmath.h"

typedef enum CameraModeArwingMapEventSlot {
    CAMERA_MODE_ARWING_NO_Z_EASE_MAP_EVENT_SLOT = 0x26,
} CameraModeArwingMapEventSlot;

CameraModeArwingState gCameraModeArwingState;

void CameraModeArwing_copyToCurrent(void* actionData, u32 recordSize) {
    if (recordSize == sizeof(CameraModeArwingPositionInput)) {
        const CameraModeArwingPositionInput* input = (const CameraModeArwingPositionInput*)actionData;
        gCameraModeArwingState.offsetX = input->offsetX;
        gCameraModeArwingState.offsetY = input->offsetY;
        gCameraModeArwingState.offsetZ = input->offsetZ;
        return;
    }
    if (recordSize == sizeof(CameraModeArwingRotationInput)) {
        const CameraModeArwingRotationInput* input = (const CameraModeArwingRotationInput*)actionData;
        gCameraModeArwingState.inputYaw = input->yaw;
        gCameraModeArwingState.inputPitch = input->pitch;
        gCameraModeArwingState.inputRoll = input->roll;
        return;
    }
    if (recordSize == sizeof(CameraModeArwingZOffsetInput)) {
        const CameraModeArwingZOffsetInput* input = (const CameraModeArwingZOffsetInput*)actionData;
        gCameraModeArwingState.posZOffset = input->offset;
        return;
    }
    {
        const CameraModeArwingZEaseInput* input = (const CameraModeArwingZEaseInput*)actionData;
        gCameraModeArwingState.zEaseDenominator = input->denominator;
        gCameraModeArwingState.zEaseNumerator = input->numerator;
    }
}

void CameraModeArwing_free(void) {
}

void CameraModeArwing_update(CameraObject* camera) {
    int targetYaw, targetPitch;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    int angleDelta;

    camera->anim.worldPosX = gCameraModeArwingState.offsetX * gCameraModeArwingState.xScale;
    camera->anim.worldPosX = camera->anim.worldPosX + gCameraModeArwingState.basePosX;
    camera->anim.worldPosY = gCameraModeArwingState.offsetY * gCameraModeArwingState.yScale;
    camera->anim.worldPosY = camera->anim.worldPosY + gCameraModeArwingState.basePosY;
    camera->anim.worldPosZ = target->anim.worldPosZ + gCameraModeArwingState.posZOffset;

    if (target->anim.mapEventSlot != CAMERA_MODE_ARWING_NO_Z_EASE_MAP_EVENT_SLOT) {
        f32 zEase = gCameraModeArwingState.zEaseNumerator / gCameraModeArwingState.zEaseDenominator;
        zEase = zEase - 1.0f;
        if (zEase < 0.0f) {
            camera->anim.worldPosZ = (f32) - (s32)gCameraModeArwingState.zScaleNear * zEase + camera->anim.worldPosZ;
        } else {
            camera->anim.worldPosZ = (f32) - (s32)gCameraModeArwingState.zScaleFar * zEase + camera->anim.worldPosZ;
        }
    }

    targetYaw = (s32)((f32)gCameraModeArwingState.inputYaw * gCameraModeArwingState.yawScale);
    targetPitch = (s32)((f32)gCameraModeArwingState.inputPitch * gCameraModeArwingState.pitchScale);

    if (arwarwing_isDead(target) != 0) {
        f32 relX, relY, relZ, relDist;
        int rotationStep;
        CameraModeArwingState* state;
        gCameraModeArwingState.rollRate = 500.0f;
        state = &gCameraModeArwingState;
        (*gCameraInterface)->getRelativePosition(camera, &relX, &relY, &relZ, &relDist, 0.0f, 0);
        camera->anim.rotZ = state->rollRate * timeDelta + (f32)camera->anim.rotZ;
        angleDelta = 0x8000 - (u16)getAngle(relX, relZ);
        targetYaw = (u16)getAngle(relY, relDist);
        angleDelta -= (u16)camera->anim.rotX;
        if (angleDelta > 0x8000) {
            angleDelta = angleDelta - 0xffff;
        }
        if (angleDelta < -0x8000) {
            angleDelta = angleDelta + 0xffff;
        }
        rotationStep = (s32)((f32)angleDelta * timeDelta);
        camera->anim.rotX = rotationStep / 16.0f + (f32) * (s16*)camera;
        angleDelta = targetYaw - (u16)camera->anim.rotY;
        if (angleDelta > 0x8000) {
            angleDelta = angleDelta - 0xffff;
        }
        if (angleDelta < -0x8000) {
            angleDelta = angleDelta + 0xffff;
        }
        rotationStep = (s32)((f32)angleDelta * timeDelta);
        camera->anim.rotY = rotationStep / 16.0f + (f32)camera->anim.rotY;
    } else if (arwarwing_isExplodingOrWarping(target) != 0) {
        gCameraModeArwingState.rollRate *= 0.98f;
        camera->anim.rotZ = gCameraModeArwingState.rollRate * timeDelta + (f32)camera->anim.rotZ;
    } else {
        int targetRoll = (s32)((f32)gCameraModeArwingState.inputRoll * gCameraModeArwingState.rollScale);
        targetRoll = targetRoll - (u16)camera->anim.rotZ;
        if (targetRoll > 0x8000) {
            targetRoll = targetRoll - 0xffff;
        }
        if (targetRoll < -0x8000) {
            targetRoll = targetRoll + 0xffff;
        }
        camera->anim.rotZ = ((f32)targetRoll * timeDelta) / 16.0f + (f32)camera->anim.rotZ;
        targetYaw = targetYaw - (u16)camera->anim.rotX;
        if (targetYaw > 0x8000) {
            targetYaw = targetYaw - 0xffff;
        }
        if (targetYaw < -0x8000) {
            targetYaw = targetYaw + 0xffff;
        }
        camera->anim.rotX = ((f32)targetYaw * timeDelta) / 16.0f + (f32) * (s16*)camera;
        targetPitch = targetPitch - (u16)camera->anim.rotY;
        if (targetPitch > 0x8000) {
            targetPitch = targetPitch - 0xffff;
        }
        if (targetPitch < -0x8000) {
            targetPitch = targetPitch + 0xffff;
        }
        camera->anim.rotY = ((f32)targetPitch * timeDelta) / 16.0f + (f32)camera->anim.rotY;
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

void CameraModeArwing_init(CameraObject* camera, int mode, int unusedArg) {
    GameObject* target = (GameObject*)camera->anim.targetObj;
    CameraModeArwingState* state;
    Vec* initialOffset;
    f32 zEaseValue;
    f32 zero;
    if (mode != 1) {
        gCameraModeArwingState.basePosX = target->anim.worldPosX;
        gCameraModeArwingState.basePosY = target->anim.worldPosY;
        gCameraModeArwingState.basePosZ = target->anim.worldPosZ;
    }
    (initialOffset = (Vec*)&(state = &gCameraModeArwingState)->initialOffsetX)->x = 0.0f;
    state->initialOffsetY = 20.0f;
    state->posZOffset = -165.0f;
    PSVECAdd(&target->anim.worldPos, initialOffset, &camera->anim.worldPos);
    gCameraModeArwingState.active = 1;
    gCameraModeArwingState.yawScale = -0.2f;
    gCameraModeArwingState.pitchScale = 0.1f;
    gCameraModeArwingState.rollScale = 0.3f;
    gCameraModeArwingState.xScale = 0.8f;
    gCameraModeArwingState.yScale = 0.65f;
    zero = 0.0f;
    gCameraModeArwingState.unk2C = zero;
    zEaseValue = 13.0f;
    gCameraModeArwingState.zEaseNumerator = zEaseValue;
    gCameraModeArwingState.zEaseDenominator = zEaseValue;
    gCameraModeArwingState.zScaleFar = 90;
    gCameraModeArwingState.zScaleNear = 100;
    gCameraModeArwingState.offsetZ = zero;
    gCameraModeArwingState.offsetY = zero;
    gCameraModeArwingState.offsetX = zero;
    camera->anim.worldPosX = target->anim.worldPosX;
    camera->anim.worldPosY = target->anim.worldPosY;
    camera->anim.worldPosZ = target->anim.worldPosZ + state->posZOffset;
}

void CameraModeArwing_release(void) {
}

void CameraModeArwing_initialise(void) {
}

CameraModeArwingDescriptor gCameraModeArwingDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeArwing_initialise,
    CameraModeArwing_release,
    NULL,
    CameraModeArwing_init,
    CameraModeArwing_update,
    CameraModeArwing_free,
    CameraModeArwing_copyToCurrent,
    NULL,
};
