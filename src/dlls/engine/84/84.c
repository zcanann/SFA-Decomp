/*
 * DLL 84 / 0x54 - unnamed camera mode.
 */
#include "main/dll/dll_0054_dll54.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/obj_list.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "string.h"
#include "sys/objects.h"

CameraMode54State* gCameraMode54State;

typedef enum CameraMode54ObjectId {
    CAMERA_MODE_54_LOOK_AT_OBJECT_ID = 0x2AB,
    CAMERA_MODE_54_ORIGIN_OBJECT_ID = 0x4DC,
} CameraMode54ObjectId;

void CameraMode54_copyToCurrent(void) {
}

void CameraMode54_free(void) {
    mm_free(gCameraMode54State);
    gCameraMode54State = NULL;
}

void CameraMode54_update(CameraObject* camera) {
    int objectIndex;
    int objectCount;
    f32 distanceZSquared, distanceXSquared;
    f32 lookAtOffsetX, lookAtOffsetY, lookAtOffsetZ;
    f32 lookAtDistance;
    f32 directionX, directionZ;
    f32 playerOffsetX, playerOffsetZ;
    f32 playerDistance, cameraDistance, proximity;
    f32 transitionWeight;
    s16 currentAngle;
    s16 angleDelta;

    if (gCameraMode54State->exitRequested != 0) {
        (*gCameraInterface)->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, 0, 0xff);
    } else {
        if (gCameraMode54State->lookAtObj == NULL) {
            int* objects = (int*)ObjList_GetObjects(&objectIndex, &objectCount);
            for (; objectIndex < objectCount; objectIndex++) {
                GameObject* object = (GameObject*)objects[objectIndex];
                if (object->anim.romDefNo == CAMERA_MODE_54_LOOK_AT_OBJECT_ID) {
                    gCameraMode54State->lookAtObj = object;
                } else if (object->anim.romDefNo == CAMERA_MODE_54_ORIGIN_OBJECT_ID) {
                    gCameraMode54State->originObj = object;
                }
            }
        }
        if (gCameraMode54State->playerObj == NULL) {
            gCameraMode54State->playerObj = Obj_GetPlayerObject();
        }
        {
            GameObject* lookAtObj = gCameraMode54State->lookAtObj;
            lookAtOffsetX = lookAtObj->anim.worldPosX - gCameraMode54State->originObj->anim.worldPosX;
            lookAtOffsetY = lookAtObj->anim.worldPosY - gCameraMode54State->originObj->anim.worldPosY;
            lookAtOffsetZ = lookAtObj->anim.worldPosZ - gCameraMode54State->originObj->anim.worldPosZ;
        }
        distanceZSquared = lookAtOffsetZ * lookAtOffsetZ;
        distanceXSquared = lookAtOffsetX * lookAtOffsetX;
        lookAtDistance = sqrtf(distanceZSquared + (lookAtOffsetY * lookAtOffsetY + distanceXSquared));
        directionX = lookAtOffsetX / lookAtDistance;
        directionZ = lookAtOffsetZ / lookAtDistance;
        playerOffsetX = -(140.0f * directionX - gCameraMode54State->originObj->anim.worldPosX) -
                        gCameraMode54State->playerObj->anim.worldPosX;
        playerOffsetZ = -(140.0f * directionZ - gCameraMode54State->originObj->anim.worldPosZ) -
                        gCameraMode54State->playerObj->anim.worldPosZ;
        playerDistance = sqrtf(playerOffsetX * playerOffsetX + playerOffsetZ * playerOffsetZ);
        proximity = (200.0f - playerDistance) / 200.0f;
        camera->fov = 45.0f + 70.0f * proximity;
        cameraDistance = -30.0f + 350.0f * proximity;
        camera->anim.worldPosX = -(directionX * cameraDistance - gCameraMode54State->originObj->anim.worldPosX);
        camera->anim.worldPosY = (20.0f + gCameraMode54State->originObj->anim.worldPosY) + 60.0f * proximity;
        camera->anim.worldPosZ = -(directionZ * cameraDistance - gCameraMode54State->originObj->anim.worldPosZ);
        camera->anim.rotX = -getAngle(lookAtOffsetX, lookAtOffsetZ);
        camera->anim.rotY = -getAngle(-(100.0f * (lookAtDistance / 400.0f) - lookAtOffsetY),
                                      sqrtf(distanceXSquared + distanceZSquared));

        if (gCameraMode54State->transitionDone == 0) {
            transitionWeight = gCameraMode54State->transitionTimer / 60.0f;
            camera->anim.worldPosX =
                transitionWeight * (gCameraMode54State->startX - camera->anim.worldPosX) + camera->anim.worldPosX;
            camera->anim.worldPosY =
                transitionWeight * (gCameraMode54State->startY - camera->anim.worldPosY) + camera->anim.worldPosY;
            camera->anim.worldPosZ =
                transitionWeight * (gCameraMode54State->startZ - camera->anim.worldPosZ) + camera->anim.worldPosZ;

            currentAngle = camera->anim.rotX;
            angleDelta = (s16)(gCameraMode54State->startYaw - (u16)currentAngle);
            if (angleDelta > 0x8000) {
                angleDelta = (s16)(angleDelta - 0xFFFF);
            }
            if (angleDelta < -0x8000) {
                angleDelta += 0xFFFF;
            }
            camera->anim.rotX = angleDelta * transitionWeight + currentAngle;

            currentAngle = camera->anim.rotY;
            angleDelta = (s16)(gCameraMode54State->startPitch - (u16)currentAngle);
            angleDelta = (angleDelta > 0x8000) ? (s16)(angleDelta - 0xFFFF) : angleDelta;
            angleDelta = (angleDelta < -0x8000) ? (s16)(angleDelta + 0xFFFF) : angleDelta;
            camera->anim.rotY = angleDelta * transitionWeight + currentAngle;

            gCameraMode54State->transitionTimer -= timeDelta;
            if (gCameraMode54State->transitionTimer < 0.0f) {
                gCameraMode54State->transitionDone = 1;
                gCameraMode54State->transitionTimer = 0.0f;
            }
        }
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       (GameObject*)camera->anim.parent);
    }
}

void CameraMode54_init(CameraObject* camera, int unusedArg, CameraObject* source) {
    if (gCameraMode54State == NULL) {
        gCameraMode54State = (CameraMode54State*)mmAlloc(sizeof(CameraMode54State), 15, 0);
    }
    memset(gCameraMode54State, 0, sizeof(CameraMode54State));
    gCameraMode54State->transitionTimer = 60.0f;
    gCameraMode54State->transitionDone = 0;
    if (source != NULL) {
        camera->anim.localPosX = source->anim.worldPosX;
        camera->anim.localPosY = source->anim.worldPosY;
        camera->anim.localPosZ = source->anim.worldPosZ;
        camera->anim.rotX = source->anim.rotX;
        camera->anim.rotY = source->anim.rotY;
        camera->anim.rotZ = source->anim.rotZ;
        camera->fov = source->fov;
    }
    gCameraMode54State->startX = camera->anim.worldPosX;
    gCameraMode54State->startY = camera->anim.worldPosY;
    gCameraMode54State->startZ = camera->anim.worldPosZ;
    gCameraMode54State->startYaw = camera->anim.rotX;
    gCameraMode54State->startPitch = camera->anim.rotY;
    gCameraMode54State->startRoll = camera->anim.rotZ;
}

void CameraMode54_release(void) {
}

void CameraMode54_initialise(void) {
}

CameraMode54Descriptor gCameraMode54Descriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraMode54_initialise,
    CameraMode54_release,
    NULL,
    CameraMode54_init,
    CameraMode54_update,
    CameraMode54_free,
    CameraMode54_copyToCurrent,
    NULL,
};
