/*
 * DLL 82 / 0x52 - force-behind camera mode.
 */
#include "main/dll/dll_0052_cameramodeforcebehind.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/dll/dll_0042_cameramodenormal.h"
#include "main/dll/player_motion.h"
#include "main/frame_timing.h"
#include "main/object_transform.h"
#include "main/vecmath.h"

f32 gCamForceBehindTraceDistance;
f32 gCamForceBehindActiveHeightOffset;
f32 gCamForceBehindPlacementRadius;

f32 gCamForceBehindOrbitRadius = 40.0f;

void CameraModeForceBehind_copyToCurrent(void) {
}

void CameraModeForceBehind_free(void) {
}

void CameraModeForceBehind_update(CameraObject* camera) {
    extern const f32 gCamForceBehindEaseRate[1];
    GameObject* target = (GameObject*)camera->anim.targetObj;
    s16 yaw;
    s16 pitch;
    s16 traceRotY;
    f32 tracePosition[3];
    f32 radians;
    f32 orbitSin;
    f32 orbitCos;
    f32 traceOriginX;
    f32 traceOriginZ;
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    f32 yawX;
    f32 yawZ;
    f32 pitchHorizontalScale;
    f32 pitchVerticalScale;
    f32 radius;
    f32 traceDeltaX;
    f32 traceDeltaZ;

    radians = 3.1415927f * (f32)(0x8000 - camera->anim.rotX) / 32768.0f;
    orbitSin = mathSinf(radians);
    orbitCos = mathCosf(radians);
    tracePosition[0] = orbitSin * gCamForceBehindOrbitRadius + (traceOriginX = target->anim.worldPosX);
    tracePosition[1] = 37.0f + target->anim.worldPosY;
    tracePosition[2] = orbitCos * gCamForceBehindOrbitRadius + (traceOriginZ = target->anim.worldPosZ);
    camcontrol_traceFromTarget(tracePosition, target, tracePosition, &traceRotY);
    traceDeltaX = tracePosition[0] - traceOriginX;
    traceDeltaZ = tracePosition[2] - traceOriginZ;
    gCamForceBehindTraceDistance = sqrtf(traceDeltaX * traceDeltaX + traceDeltaZ * traceDeltaZ);
    gCamForceBehindPlacementRadius = gCamForceBehindTraceDistance;

    Player_GetAimAngles(target, &yaw, &pitch);
    yaw = (s16)((0x8000 - target->anim.rotX) + (yaw >> 1));
    pitch = (s16)(pitch >> 1);
    targetX = target->anim.worldPosX;
    targetY = target->anim.worldPosY + gCamForceBehindActiveHeightOffset;
    targetZ = target->anim.worldPosZ;

    yaw = (s16)(yaw - (u16)camera->anim.rotX);
    if (yaw > 0x8000) {
        yaw = yaw - 0xffff;
    }
    if (yaw < -0x8000) {
        yaw = yaw + 0xffff;
    }
    camera->anim.rotX = (f32)(s32)camera->anim.rotX + interpolate((f32)yaw, gCamForceBehindEaseRate[0], timeDelta);

    pitch = (s16)(pitch - (u16)camera->anim.rotY);
    if (pitch > 0x8000) {
        pitch = pitch - 0xffff;
    }
    if (pitch < -0x8000) {
        pitch = pitch + 0xffff;
    }
    camera->anim.rotY = (f32)(s32)camera->anim.rotY + interpolate((f32)pitch, gCamForceBehindEaseRate[0], timeDelta);

    yawX = mathSinf(3.1415927f * (f32)(s32)(camera->anim.rotX - 0x4000) / 32768.0f);
    yawZ = mathCosf(3.1415927f * (f32)(s32)(camera->anim.rotX - 0x4000) / 32768.0f);
    pitchHorizontalScale = mathCosf(3.1415927f * (f32)(s32)camera->anim.rotY / 32768.0f);
    pitchVerticalScale = mathSinf(3.1415927f * (f32)(s32)camera->anim.rotY / 32768.0f);
    radius = gCamForceBehindPlacementRadius;
    {
        f32 verticalOffset = radius * pitchVerticalScale;
        f32 horizontalRadius = radius * pitchHorizontalScale;
        f32 xOffset = horizontalRadius * yawZ;
        horizontalRadius = horizontalRadius * yawX;
        camera->anim.worldPosX = targetX + xOffset;
        camera->anim.worldPosY = targetY + verticalOffset;
        camera->anim.worldPosZ = targetZ + horizontalRadius;
    }
    camcontrol_traceFromTarget(&camera->anim.worldPosX, target, &camera->anim.worldPosX, &camera->anim.rotY);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

const f32 gCamForceBehindEaseRate[] = {0.25f};

void CameraModeForceBehind_init(CameraObject* camera, int unused, CameraModeForceBehindInitParams* params) {
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 radians;
    f32 orbitSin;
    f32 orbitCos;
    f32 targetX;
    f32 targetZ;
    f32 tracePosition[3];
    f32 traceRotY;
    f32 traceDeltaX;
    f32 traceDeltaZ;

    {
        s16 rotX = target->anim.rotX;
        radians = 3.1415927f * rotX / 32768.0f;
    }
    orbitSin = mathSinf(radians);
    orbitCos = mathCosf(radians);
    tracePosition[0] = orbitSin * gCamForceBehindOrbitRadius + (targetX = target->anim.worldPosX);
    tracePosition[1] = 37.0f + target->anim.worldPosY;
    targetZ = target->anim.worldPosZ;
    tracePosition[2] = orbitCos * gCamForceBehindOrbitRadius + targetZ;
    camcontrol_traceFromTarget(tracePosition, target, tracePosition, &traceRotY);
    traceDeltaX = tracePosition[0] - targetX;
    traceDeltaZ = tracePosition[2] - targetZ;
    gCamForceBehindTraceDistance = sqrtf(traceDeltaX * traceDeltaX + traceDeltaZ * traceDeltaZ);
    if (params != NULL) {
        gCamForceBehindOrbitRadius = params->orbitRadius;
        gCamForceBehindActiveHeightOffset = params->heightOffset;
    } else {
        gCamForceBehindOrbitRadius = 40.0f;
        gCamForceBehindActiveHeightOffset = 37.0f;
    }
}

void CameraModeForceBehind_release(void) {
}

void CameraModeForceBehind_initialise(void) {
}

CameraModeForceBehindDescriptor gCameraModeForceBehindDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeForceBehind_initialise,
    CameraModeForceBehind_release,
    NULL,
    CameraModeForceBehind_init,
    CameraModeForceBehind_update,
    CameraModeForceBehind_free,
    CameraModeForceBehind_copyToCurrent,
    NULL,
};
