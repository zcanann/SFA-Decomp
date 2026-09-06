/*
 * DLL 72 / 0x48 - static camera mode.
 */
#include "main/dll/dll_0048_cameramodestatic.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_025A_staticcamera.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/objtype.h"
#include "main/object_transform.h"
#include "main/vecmath.h"

CameraModeStaticState* gCameraModeStaticState;

GameObject* camStaticFindNearestAnchor(f32 x, f32 y, f32 z, int anchorId, int classId) {
    int i;
    GameObject* nearest;
    f32 nearestDistance;
    int count;
    GameObject* candidate;
    GameObject** objects;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 squaredY;
    f32 distance;

    nearestDistance = 100000.0f;
    nearest = NULL;
    objects = (GameObject**)objGetAllOfType(STATIC_CAMERA_OBJECT_GROUP, &count);
    for (i = 0; i < count; i++) {
        candidate = objects[i];
        if (candidate->anim.classId == classId &&
            ((StaticCameraPlacement*)candidate->anim.placementData)->anchorId == anchorId) {
            dx = x - candidate->anim.worldPosX;
            dy = y - candidate->anim.worldPosY;
            dz = z - candidate->anim.worldPosZ;
            squaredY = dy * dy;
            distance = sqrtf(squaredY + dx * dx + dz * dz);
            if (distance < nearestDistance) {
                nearestDistance = distance;
                nearest = candidate;
            }
        }
    }
    return nearest;
}

void CameraModeStatic_copyToCurrent(void) {
}

void CameraModeStatic_free(void) {
    mm_free(gCameraModeStaticState);
    gCameraModeStaticState = NULL;
}

void CameraModeStatic_update(CameraObject* camera) {
    int angle;
    u32 pitch;
    StaticCameraPlacement* placement;
    GameObject* target;
    int rollDelta;
    f32 dx;
    f32 dy;
    f32 dz;

    if (gCameraModeStaticState->missingAnchor != 0) {
        (*gCameraInterface)->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, 0, 0xff);
    } else {
        target = (GameObject*)camera->anim.targetObj;
        placement = (StaticCameraPlacement*)gCameraModeStaticState->anchor->anim.placementData;
        if ((placement->modeFlags & CAMERA_MODE_STATIC_TRACK_YAW) == 0) {
            camera->anim.rotX = placement->cameraModeRotation.yaw + 0x8000;
        }
        if ((placement->modeFlags & CAMERA_MODE_STATIC_TRACK_PITCH) == 0) {
            camera->anim.rotY = placement->cameraModeRotation.pitch;
        }
        if ((placement->modeFlags & CAMERA_MODE_STATIC_TRACK_ROLL) == 0) {
            camera->anim.rotZ = placement->cameraModeRotation.roll;
        }
        camera->anim.worldPosX = gCameraModeStaticState->anchor->anim.worldPosX;
        camera->anim.worldPosY = gCameraModeStaticState->anchor->anim.worldPosY;
        camera->anim.worldPosZ = gCameraModeStaticState->anchor->anim.worldPosZ;
        camera->fov = (f32)(u32)placement->fov;
        dx = camera->anim.worldPosX - target->anim.worldPosX;
        dy = camera->anim.worldPosY - target->anim.worldPosY;
        dz = camera->anim.worldPosZ - target->anim.worldPosZ;
        if ((placement->modeFlags & CAMERA_MODE_STATIC_TRACK_YAW) != 0) {
            angle = getAngle(dx, dz);
            camera->anim.rotX = 0x8000 - angle;
        }
        if ((placement->modeFlags & CAMERA_MODE_STATIC_TRACK_PITCH) != 0) {
            pitch = getAngle(dy, sqrtf(dx * dx + dz * dz)) & 0xffff;
            angle = (pitch - (int)placement->cameraModeRotation.pitch) - (u32)(u16)camera->anim.rotY;
            if (angle > 0x8000) {
                angle += -0xffff;
            }
            if (angle < -0x8000) {
                angle += 0xffff;
            }
            camera->anim.rotY += (int)(angle * framesThisStep) >> 3;
        }
        if ((placement->modeFlags & CAMERA_MODE_STATIC_TRACK_ROLL) != 0) {
            rollDelta = camera->anim.rotZ - (u32)(u16)target->anim.rotZ;
            if (rollDelta > 0x8000) {
                rollDelta += -0xffff;
            }
            if (rollDelta < -0x8000) {
                rollDelta += 0xffff;
            }
            camera->anim.rotZ += (int)(rollDelta * framesThisStep) >> 3;
        }
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       (GameObject*)camera->anim.parent);
    }
    return;
}

void CameraModeStatic_init(CameraObject* camera, int unused, const int* anchorId) {
    StaticCameraPlacement* placement;
    GameObject* target;
    GameObject* anchor;
    s16 yaw;
    s16 pitch;
    s16 roll;
    f32 dx;
    f32 dy;
    f32 dz;

    target = (GameObject*)camera->anim.targetObj;
    if (gCameraModeStaticState == NULL) {
        gCameraModeStaticState = (CameraModeStaticState*)mmAlloc(sizeof(CameraModeStaticState), 0xF, 0);
    }
    gCameraModeStaticState->active = 1;
    gCameraModeStaticState->missingAnchor = 0;
    anchor = camStaticFindNearestAnchor(target->anim.worldPosX, target->anim.worldPosY, target->anim.worldPosZ,
                                        *anchorId, STATIC_CAMERA_CLASS_ID);
    if (anchor == NULL) {
        gCameraModeStaticState->missingAnchor = 1;
        return;
    }
    gCameraModeStaticState->anchor = anchor;
    placement = (StaticCameraPlacement*)anchor->anim.placementData;
    dx = anchor->anim.worldPosX - target->anim.worldPosX;
    dy = anchor->anim.worldPosY - target->anim.worldPosY;
    dz = anchor->anim.worldPosZ - target->anim.worldPosZ;
    if ((placement->modeFlags & CAMERA_MODE_STATIC_TRACK_YAW) != 0) {
        yaw = 0x8000 - getAngle(dx, dz);
    } else {
        yaw = placement->cameraModeRotation.yaw + 0x8000;
    }
    if ((placement->modeFlags & CAMERA_MODE_STATIC_TRACK_PITCH) != 0) {
        pitch = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
        pitch -= placement->cameraModeRotation.pitch;
    } else {
        pitch = placement->cameraModeRotation.pitch;
    }
    if ((placement->modeFlags & CAMERA_MODE_STATIC_TRACK_ROLL) != 0) {
        roll = target->anim.rotZ;
    } else {
        roll = placement->cameraModeRotation.roll;
    }
    {
        f32 fov = (f32)(u32)placement->fov;
        camera->anim.worldPosX = anchor->anim.worldPosX;
        camera->anim.worldPosY = anchor->anim.worldPosY;
        camera->anim.worldPosZ = anchor->anim.worldPosZ;
        camera->anim.rotX = yaw;
        camera->anim.rotY = pitch;
        camera->anim.rotZ = roll;
        camera->fov = fov;
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

void CameraModeStatic_release(void) {
}

void CameraModeStatic_initialise(void) {
}

CameraModeStaticDescriptor gCameraModeStaticDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeStatic_initialise,
    CameraModeStatic_release,
    NULL,
    CameraModeStatic_init,
    CameraModeStatic_update,
    CameraModeStatic_free,
    CameraModeStatic_copyToCurrent,
    NULL,
};
