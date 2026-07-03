/*
 * cameramodedebug (DLL 0x46) - free-orbit debug camera.
 * The player holds Z (bit 3) to zoom in and R (bit 2) to zoom out;
 * the C-stick pans yaw/pitch; pressing B (bit 1) exits back to the
 * default camcontrol action (0x42).  Orbit radius is spring-damped.
 * CameraModeStatic symbols at the end are co-linked with this DLL.
 */
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/game_object.h"
#include "main/dll/CAM/camdebug_state.h"
#include "main/dll/CAM/camstatic_state.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/dll/fx_800944A0_shared.h"

/* pad.h declares getButtonsJustPressed as u32; the u16 override in
   CameraModeDebug_update is load-bearing for the mask comparison. */
extern u32 getButtonsHeld(int port);
extern u8 padGetCX(int port);
extern u8 padGetCY(int port);



/* camera mode id to restore on B-press exit */
#define CAMCONTROL_ACTION_DEFAULT 0x42

extern CameraModeDebugState* gCamDebugState;
extern f32 lbl_803E1840;
extern f32 gCamDebugZoomInRate;
extern f32 gCamDebugZoomOutRate;
extern f32 gCamDebugRadiusDampFast;
extern f32 gCamDebugRadiusDampSlow;
extern f32 gCamDebugOrbitRadiusMin;
extern f32 gCamDebugOrbitRadiusMax;
extern f32 gCamDebugPi;
extern f32 gCamDebugAngleUnitScale;
extern f32 gCamDebugOrbitRadiusInit;

#pragma opt_common_subs off
#pragma opt_propagation off
void CameraModeDebug_update(CameraObject* cam)
{
    extern u16 getButtonsJustPressed(int port);
    GameObject* state;
    u16 held;
    f32 move;
    f32 absMove;
    f32 absVel;
    f32 factor;
    f32 radius;

    move = lbl_803E1840;
    state = (GameObject*)cam->anim.targetObj;
    held = getButtonsHeld(0);
    if ((getButtonsJustPressed(0) & 2) != 0)
    {
        (*gCameraInterface)->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, 0, 0xff);
        return;
    }
    if ((held & 8) != 0)
    {
        move = gCamDebugZoomInRate * gCamDebugState->orbitRadius;
    }
    if ((held & 4) != 0)
    {
        move = gCamDebugZoomOutRate * gCamDebugState->orbitRadius;
    }
    absMove = (move < lbl_803E1840) ? -move : move;
    {
        CameraModeDebugState* st = gCamDebugState;
        f32 vel = st->radiusVelocity;
        absVel = (vel < lbl_803E1840) ? -vel : vel;
        factor = (absVel > absMove) ? gCamDebugRadiusDampFast : gCamDebugRadiusDampSlow;
        st->radiusVelocity = factor * (move - vel) + st->radiusVelocity;
    }
    gCamDebugState->orbitRadius = gCamDebugState->orbitRadius + gCamDebugState->radiusVelocity;
    if (gCamDebugState->orbitRadius < gCamDebugOrbitRadiusMin)
    {
        gCamDebugState->orbitRadius = gCamDebugOrbitRadiusMin;
    }
    if (gCamDebugState->orbitRadius > gCamDebugOrbitRadiusMax)
    {
        gCamDebugState->orbitRadius = gCamDebugOrbitRadiusMax;
    }
    {
        u16 dx = (u16)((s8)padGetCX(0) * 3);
        u16 dy = (u16)((s8)padGetCY(0) * 3);
        cam->anim.rotX = (s16)(cam->anim.rotX - dx);
        cam->anim.rotY = (s16)(cam->anim.rotY + dy);
    }
    {
        f32 cosYaw = mathSinf(gCamDebugPi * (f32)(s32)(cam->anim.rotX - 0x4000) / gCamDebugAngleUnitScale);
        f32 sinYaw = mathCosf(gCamDebugPi * (f32)(s32)(cam->anim.rotX - 0x4000) / gCamDebugAngleUnitScale);
        f32 sinPitch = mathCosf(gCamDebugPi * (f32)(s32)cam->anim.rotY / gCamDebugAngleUnitScale);
        f32 cosPitch = mathSinf(gCamDebugPi * (f32)(s32)cam->anim.rotY / gCamDebugAngleUnitScale);
        f32 vy, h, px;
        radius = gCamDebugState->orbitRadius;
        vy = radius * cosPitch;
        h = radius * sinPitch;
        px = h * sinYaw;
        h = h * cosYaw;
        cam->anim.worldPosX = state->anim.worldPosX + px;
        {
            f32 base28 = gCamDebugOrbitRadiusMin + state->anim.worldPosY;
            cam->anim.worldPosY = base28 + vy;
        }
        cam->anim.worldPosZ = state->anim.worldPosZ + h;
    }
    Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY, cam->anim.worldPosZ,
                                   &cam->anim.localPosX, &cam->anim.localPosY, &cam->anim.localPosZ,
                                   *(int*)&cam->anim.parent);
}
#pragma opt_propagation reset
#pragma opt_common_subs reset

void CameraModeDebug_init(void)
{
    if (gCamDebugState == NULL)
    {
        gCamDebugState = (CameraModeDebugState*)mmAlloc(sizeof(CameraModeDebugState), 0xf, 0);
    }
    gCamDebugState->orbitRadius = gCamDebugOrbitRadiusInit;
    gCamDebugState->radiusVelocity = lbl_803E1840;
    return;
}

void CameraModeDebug_copyToCurrent_nop(void)
{
}

void CameraModeDebug_release_nop(void)
{
}

void CameraModeDebug_initialise_nop(void)
{
}


void CameraModeDebug_free(void)
{
    mm_free(gCamDebugState);
    gCamDebugState = 0;
}

