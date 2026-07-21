/*
 * DLL 0x0052 (cameramodeforcebehind) - "force behind" camera mode handlers
 * 0x8010FC74..0x801101E4. Init seeds the camera's orbit radius from the
 * target's facing, then update keeps the camera locked behind the target:
 * it eases yaw/pitch toward the target's aim angles, re-derives the orbit
 * position, traces against geometry (camcontrol_traceFromTarget) and converts
 * the result back to the target's local space. The empty release/free/copy
 * stubs are the mode's vtable no-ops.
 */
#include "main/camera_object.h"
#include "main/resource.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/dll/player_motion.h"
#include "main/dll/CAM/cutCam.h"
#include "main/frame_timing.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "main/dll/dll_0052_cameramodeforcebehind.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

f32 gCamForceBehindTraceDistance;
f32 gCamForceBehindActiveHeightOffset;
f32 gCamForceBehindPlacementRadius;

f32 gCamForceBehindOrbitRadius = 40.0f;
extern f32 gCamForceBehindOrbitRadius;        /* orbit radius */
extern f32 gCamForceBehindActiveHeightOffset; /* active height offset */
extern f32 gCamForceBehindTraceDistance;      /* derived horizontal trace distance */
extern f32 gCamForceBehindPlacementRadius;    /* derived orbit radius used to place the camera */
void CameraModeForceBehind_copyToCurrent(void)
{
}

void CameraModeForceBehind_free(void)
{
}

void CameraModeForceBehind_update(u8* obj)
{
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    s16 yaw;
    s16 pitch;
    s16 extra;
    f32 pos[3];
    f32 angle;
    f32 cosv, sinv;
    f32 sx, sz;
    f32 baseX, baseY, baseZ;
    f32 cosYaw, sinYaw, sinPitch, cosPitch;
    f32 radius;
    f32 dx, dz;

    angle = 3.1415927f * (f32)(0x8000 - camera->anim.rotX) / 32768.0f;
    cosv = mathSinf(angle);
    sinv = mathCosf(angle);
    pos[0] = cosv * gCamForceBehindOrbitRadius + (sx = target->anim.worldPosX);
    pos[1] = 37.0f + target->anim.worldPosY;
    pos[2] = sinv * gCamForceBehindOrbitRadius + (sz = target->anim.worldPosZ);
    camcontrol_traceFromTarget(pos, target, pos, &extra);
    dx = pos[0] - sx;
    dz = pos[2] - sz;
    gCamForceBehindTraceDistance = sqrtf(dx * dx + dz * dz);
    gCamForceBehindPlacementRadius = gCamForceBehindTraceDistance;

    Player_GetAimAngles((int)target, &yaw, &pitch);
    yaw = (s16)((0x8000 - target->anim.rotX) + (yaw >> 1));
    pitch = (s16)(pitch >> 1);
    baseX = target->anim.worldPosX;
    baseY = target->anim.worldPosY + gCamForceBehindActiveHeightOffset;
    baseZ = target->anim.worldPosZ;

    yaw = (s16)(yaw - (u16)camera->anim.rotX);
    if (yaw > 0x8000)
    {
        yaw = yaw - 0xffff;
    }
    if (yaw < -0x8000)
    {
        yaw = yaw + 0xffff;
    }
    camera->anim.rotX = (f32)(s32)camera->anim.rotX + interpolate((f32)yaw, 0.25f, timeDelta);

    pitch = (s16)(pitch - (u16)camera->anim.rotY);
    if (pitch > 0x8000)
    {
        pitch = pitch - 0xffff;
    }
    if (pitch < -0x8000)
    {
        pitch = pitch + 0xffff;
    }
    camera->anim.rotY = (f32)(s32)camera->anim.rotY + interpolate((f32)pitch, 0.25f, timeDelta);

    cosYaw = mathSinf(3.1415927f * (f32)(s32)(camera->anim.rotX - 0x4000) / 32768.0f);
    sinYaw = mathCosf(3.1415927f * (f32)(s32)(camera->anim.rotX - 0x4000) / 32768.0f);
    sinPitch = mathCosf(3.1415927f * (f32)(s32)camera->anim.rotY / 32768.0f);
    cosPitch = mathSinf(3.1415927f * (f32)(s32)camera->anim.rotY / 32768.0f);
    radius = gCamForceBehindPlacementRadius;
    {
        f32 ry = radius * cosPitch;
        f32 rh = radius * sinPitch;
        f32 rx = rh * sinYaw;
        rh = rh * cosYaw;
        camera->anim.worldPosX = baseX + rx;
        camera->anim.worldPosY = baseY + ry;
        camera->anim.worldPosZ = baseZ + rh;
    }
    camcontrol_traceFromTarget(&camera->anim.worldPosX, target, &camera->anim.worldPosX, &camera->anim.rotY);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

const f32 gCamForceBehindZero = 0.0f;

void CameraModeForceBehind_init(u8* obj, int unused, f32* params)
{
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 angle;
    f32 cosv, sinv;
    f32 baseX, baseZ;
    f32 pos[3];
    f32 extra;
    f32 dx, dz;

    {
        s16 a = target->anim.rotX;
        angle = 3.1415927f * a / 32768.0f;
    }
    cosv = mathSinf(angle);
    sinv = mathCosf(angle);
    pos[0] = cosv * gCamForceBehindOrbitRadius + (baseX = target->anim.worldPosX);
    pos[1] = 37.0f + target->anim.worldPosY;
    baseZ = target->anim.worldPosZ;
    pos[2] = sinv * gCamForceBehindOrbitRadius + baseZ;
    camcontrol_traceFromTarget(pos, target, pos, &extra);
    dx = pos[0] - baseX;
    dz = pos[2] - baseZ;
    gCamForceBehindTraceDistance = sqrtf(dx * dx + dz * dz);
    if (params != NULL)
    {
        gCamForceBehindOrbitRadius = params[0];
        gCamForceBehindActiveHeightOffset = params[1];
    }
    else
    {
        gCamForceBehindOrbitRadius = 40.0f;
        gCamForceBehindActiveHeightOffset = 37.0f;
    }
}

void CameraModeForceBehind_release(void)
{
}

void CameraModeForceBehind_initialise(void)
{
}

ResourceDescriptorCallbacks8 lbl_80319EC8 = {{0x00000000, 0x00000000, 0x00000000, 0x00060000},
        {(ResourceDescriptorCallback)CameraModeForceBehind_initialise, (ResourceDescriptorCallback)CameraModeForceBehind_release,
        0x00000000, (ResourceDescriptorCallback)CameraModeForceBehind_init, (ResourceDescriptorCallback)CameraModeForceBehind_update,
        (ResourceDescriptorCallback)CameraModeForceBehind_free, (ResourceDescriptorCallback)CameraModeForceBehind_copyToCurrent, 0x00000000}};
