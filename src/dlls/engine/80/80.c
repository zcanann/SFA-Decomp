/*
 * DLL 80 / 0x50 - crawl camera mode.
 */
#include "main/dll/dll_0050_cameramodecrawl.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0042_cameramodenormal.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "string.h"
#include "main/vecmath.h"

CameraModeCrawlState* gCameraModeCrawlState;

typedef struct CameraModeCrawlDefaultHandlerVTable {
    void (*slots[6])(void);
    void (*updatePitch)(f32 targetY, f32 distance, CameraObject* camera);
} CameraModeCrawlDefaultHandlerVTable;

typedef struct CameraModeCrawlDefaultHandler {
    CameraModeCrawlDefaultHandlerVTable* vtable;
} CameraModeCrawlDefaultHandler;

typedef struct CameraModeCrawlDefaultHandlerEntry {
    u16 actionId;
    u8 pad02[2];
    CameraModeCrawlDefaultHandler* handler;
    u8 priority;
    u8 pad09[3];
} CameraModeCrawlDefaultHandlerEntry;

void CameraModeCrawl_copyToCurrent(void* actionData, int recordSize) {
    CameraObject* camera;
    GameObject* target;
    int originalYaw;
    f32 sinYaw;
    f32 cosYaw;
    f32 targetPosition[3];

    if (actionData == NULL) {
        return;
    }
    camera = (*gCameraInterface)->getCamera();
    target = (GameObject*)camera->anim.targetObj;
    originalYaw = target->anim.rotX;

    if (recordSize == 0) {
        sinYaw = mathSinf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
        cosYaw = mathCosf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
    } else {
        sinYaw = -mathSinf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
        cosYaw = -mathCosf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
    }
    target->anim.rotX = getAngle(sinYaw, cosYaw);
    camcontrol_getTargetPosition(camera, &target->anim, targetPosition, NULL);
    target->anim.rotX = originalYaw;
    {
        f32 coordinate;

        coordinate = targetPosition[0];
        camera->anim.worldPosX = coordinate;
        camera->probePosX = coordinate;
        coordinate = targetPosition[1];
        camera->anim.worldPosY = coordinate;
        camera->probePosY = coordinate;
        coordinate = targetPosition[2];
        camera->anim.worldPosZ = coordinate;
        camera->probePosZ = coordinate;
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
    gCameraModeCrawlState->flags.useDefaultHandler = 1;
}

void CameraModeCrawl_free(void) {
    mm_free(gCameraModeCrawlState);
    gCameraModeCrawlState = NULL;
}

void CameraModeCrawl_update(CameraObject* camera) {
    GameObject* target = (GameObject*)camera->anim.targetObj;
    int yawDelta;
    f32 relativeX;
    f32 relativeY;
    f32 relativeZ;
    f32 relativeDistanceXZ;
    int defaultHandler;

    if (target == NULL) {
        return;
    }
    if (gCameraModeCrawlState->flags.useDefaultHandler == 0) {
        camera->anim.worldPosX =
            13.0f * mathSinf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f) + target->anim.worldPosX;
        camera->anim.worldPosZ =
            13.0f * mathCosf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f) + target->anim.worldPosZ;
        camera->anim.worldPosY = 20.0f + target->anim.worldPosY;
        relativeX = camera->anim.localPosX - target->anim.worldPosX;
        relativeZ = camera->anim.localPosZ - target->anim.worldPosZ;
        {
            int targetYaw = 0x8000 - (u16)getAngle(relativeX, relativeZ);
            yawDelta = targetYaw - (u16)camera->anim.rotX;
        }
        if (yawDelta > 0x8000) {
            yawDelta = yawDelta - 0xffff;
        }
        if (yawDelta < -0x8000) {
            yawDelta = yawDelta + 0xffff;
        }
        camera->anim.rotX = (s16)((f32)(s32)camera->anim.rotX + interpolate((f32)(s32)yawDelta, 0.125f, timeDelta));
        camera->anim.rotX = (s16)(0x8000 - getAngle(relativeX, relativeZ));
        camera->anim.rotY = 2048;
    } else {
        defaultHandler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        (*gCameraInterface)
            ->getRelativePosition(camera, &relativeX, &relativeY, &relativeZ, &relativeDistanceXZ, 35.0f, 0);
        {
            int targetYaw = 0x8000 - (u16)getAngle(relativeX, relativeZ);
            yawDelta = targetYaw - (u16)camera->anim.rotX;
        }
        if (yawDelta > 0x8000) {
            yawDelta = yawDelta - 0xffff;
        }
        if (yawDelta < -0x8000) {
            yawDelta = yawDelta + 0xffff;
        }
        camera->anim.rotX += yawDelta;
        (*(void (**)(CameraObject*, f32, f32))(*(int*)(*(int*)(defaultHandler + 4)) + 24))(
            camera, target->anim.worldPosY, relativeDistanceXZ);
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

void CameraModeCrawl_init(void) {
    if (gCameraModeCrawlState == NULL) {
        gCameraModeCrawlState = (CameraModeCrawlState*)mmAlloc(sizeof(CameraModeCrawlState), 15, 0);
        memset(gCameraModeCrawlState, 0, sizeof(CameraModeCrawlState));
    }
}

void CameraModeCrawl_release(void) {
}

void CameraModeCrawl_initialise(void) {
}

CameraModeCrawlDescriptor gCameraModeCrawlDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeCrawl_initialise,
    CameraModeCrawl_release,
    NULL,
    CameraModeCrawl_init,
    CameraModeCrawl_update,
    CameraModeCrawl_free,
    CameraModeCrawl_copyToCurrent,
    NULL,
};
