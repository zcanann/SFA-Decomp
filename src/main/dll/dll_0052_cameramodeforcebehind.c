/*
 * DLL 0x0052 (cameramodeforcebehind) - "force behind" camera mode handlers
 * 0x8010FC74..0x801101E4. Init seeds the camera's orbit radius from the
 * target's facing, then update keeps the camera locked behind the target:
 * it eases yaw/pitch toward the target's aim angles, re-derives the orbit
 * position, traces against geometry (camcontrol_traceFromTarget) and converts
 * the result back to the target's local space. The empty release/free/copy
 * stubs are the mode's vtable no-ops. fn_801101E8 (at 0x801101E8) is a related
 * free-function just past the mode's range that frees the shared cloudrunner
 * state (lbl_803DD5B8).
 */
#include "main/camera_object.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/dll/player_motion.h"
#include "main/object_transform.h"
#include "main/engine_shared.h"



extern void camcontrol_traceFromTarget();
extern f32 interpolate(f32 a, f32 t, f32 exp);
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern f32 gCamForceBehindPi; /* binary-angle -> radians scale (numerator) */
extern f32 gCamForceBehindBamsToRadDivisor; /* binary-angle -> radians divisor (half-circle = 0x8000) */
extern f32 gCamForceBehindHeightOffset; /* camera height offset above the target */
extern f32 gCamForceBehindDefaultOrbitRadius; /* default orbit radius (when no override is supplied) */
extern f32 gCamForceBehindOrbitRadius; /* orbit radius */
extern f32 gCamForceBehindActiveHeightOffset; /* active height offset */
extern f32 gCamForceBehindTraceDistance; /* derived horizontal trace distance */
extern f32 gCamForceBehindPlacementRadius; /* derived orbit radius used to place the camera */
extern f32 gCamForceBehindEaseRate; /* yaw/pitch ease rate fed to interpolate() */

void CameraModeForceBehind_func06_nop(void);
void CameraModeForceBehind_func05_nop(void);
void CameraModeForceBehind_release(void);
void CameraModeForceBehind_initialise(void);
void CameraModeForceBehind_copyToCurrent(void);
void CameraModeForceBehind_free(void);
void fn_801101E8(void);
void CameraModeForceBehind_init(u8* obj, int p2, f32* p3);
void CameraModeForceBehind_update(u8* obj);

void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void CameraModeForceBehind_release(void)
{
}

void CameraModeForceBehind_initialise(void)
{
}

void CameraModeForceBehind_copyToCurrent(void)
{
}

void CameraModeForceBehind_free(void)
{
}

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57: u32 form needed for codegen; mm.h declares void* */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

#pragma opt_propagation off
void CameraModeForceBehind_init(u8* obj, int p2, f32* p3)
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
        angle = gCamForceBehindPi * a / gCamForceBehindBamsToRadDivisor;
    }
    cosv = mathSinf(angle);
    sinv = mathCosf(angle);
    pos[0] = cosv * gCamForceBehindOrbitRadius + (baseX = target->anim.worldPosX);
    pos[1] = gCamForceBehindHeightOffset + target->anim.worldPosY;
    baseZ = target->anim.worldPosZ;
    pos[2] = sinv * gCamForceBehindOrbitRadius + baseZ;
    camcontrol_traceFromTarget(pos, target, pos, &extra);
    dx = pos[0] - baseX;
    dz = pos[2] - baseZ;
    gCamForceBehindTraceDistance = sqrtf(dx * dx + dz * dz);
    if (p3 != NULL)
    {
        gCamForceBehindOrbitRadius = p3[0];
        gCamForceBehindActiveHeightOffset = p3[1];
    }
    else
    {
        gCamForceBehindOrbitRadius = gCamForceBehindDefaultOrbitRadius;
        gCamForceBehindActiveHeightOffset = gCamForceBehindHeightOffset;
    }
}
#pragma opt_propagation reset

#pragma opt_common_subs off
#pragma opt_propagation off
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

    angle = gCamForceBehindPi * (f32)(0x8000 - camera->anim.rotX) / gCamForceBehindBamsToRadDivisor;
    cosv = mathSinf(angle);
    sinv = mathCosf(angle);
    pos[0] = cosv * gCamForceBehindOrbitRadius + (sx = target->anim.worldPosX);
    pos[1] = gCamForceBehindHeightOffset + target->anim.worldPosY;
    pos[2] = sinv * gCamForceBehindOrbitRadius + (sz = target->anim.worldPosZ);
    camcontrol_traceFromTarget(pos, target, pos, &extra);
    gCamForceBehindTraceDistance = sqrtf((pos[0] - sx) * (pos[0] - sx) + (pos[2] - sz) * (pos[2] - sz));
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
    camera->anim.rotX = (f32)(s32)camera->anim.rotX + interpolate((f32)yaw, gCamForceBehindEaseRate, timeDelta);

    pitch = (s16)(pitch - (u16)camera->anim.rotY);
    if (pitch > 0x8000)
    {
        pitch = pitch - 0xffff;
    }
    if (pitch < -0x8000)
    {
        pitch = pitch + 0xffff;
    }
    camera->anim.rotY = (f32)(s32)camera->anim.rotY +
                        interpolate((f32)pitch, gCamForceBehindEaseRate, timeDelta);

    cosYaw = mathSinf(gCamForceBehindPi * (f32)(s32)(camera->anim.rotX - 0x4000) / gCamForceBehindBamsToRadDivisor);
    sinYaw = mathCosf(gCamForceBehindPi * (f32)(s32)(camera->anim.rotX - 0x4000) / gCamForceBehindBamsToRadDivisor);
    sinPitch = mathCosf(gCamForceBehindPi * (f32)(s32)camera->anim.rotY / gCamForceBehindBamsToRadDivisor);
    cosPitch = mathSinf(gCamForceBehindPi * (f32)(s32)camera->anim.rotY / gCamForceBehindBamsToRadDivisor);
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
#pragma opt_propagation reset
#pragma opt_common_subs reset
