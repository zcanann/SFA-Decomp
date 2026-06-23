/*
 * cameramodedebug (DLL 0x46) - free-orbit debug camera.
 * The player holds Z (bit 3) to zoom in and R (bit 2) to zoom out;
 * the C-stick pans yaw/pitch; pressing B (bit 1) exits back to the
 * default camcontrol action (0x42).  Orbit radius is spring-damped.
 * CameraModeStatic symbols at the end are co-linked with this DLL.
 */
#include "main/camera_interface.h"
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
void CameraModeDebug_update(short* camObj)
{
    extern u16 getButtonsJustPressed(int port);
    u8* cam = (u8*)camObj;
    u8* state;
    u16 held;
    f32 move;
    f32 absMove;
    f32 absVel;
    f32 factor;
    f32 radius;

    move = lbl_803E1840;
    state = *(u8**)(cam + 164);
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
        *(s16*)cam = (s16)(*(s16*)cam - dx);
        *(s16*)(cam + 2) = (s16)(*(s16*)(cam + 2) + dy);
    }
    {
        f32 cosYaw = mathSinf(gCamDebugPi * (f32)(s32)(*(s16*)cam - 0x4000) / gCamDebugAngleUnitScale);
        f32 sinYaw = mathCosf(gCamDebugPi * (f32)(s32)(*(s16*)cam - 0x4000) / gCamDebugAngleUnitScale);
        f32 sinPitch = mathCosf(gCamDebugPi * (f32)(s32)*(s16*)(cam + 2) / gCamDebugAngleUnitScale);
        f32 cosPitch = mathSinf(gCamDebugPi * (f32)(s32)*(s16*)(cam + 2) / gCamDebugAngleUnitScale);
        f32 vy, h, px, pz;
        radius = gCamDebugState->orbitRadius;
        vy = radius * cosPitch;
        h = radius * sinPitch;
        px = h * sinYaw;
        pz = h * cosYaw;
        *(f32*)(cam + 24) = *(f32*)(state + 24) + px;
        {
            f32 base28 = gCamDebugOrbitRadiusMin + *(f32*)(state + 28);
            *(f32*)(cam + 28) = base28 + vy;
        }
        *(f32*)(cam + 32) = *(f32*)(state + 32) + pz;
    }
    Obj_TransformWorldPointToLocal(*(f32*)(cam + 24), *(f32*)(cam + 28), *(f32*)(cam + 32),
                                   (f32*)(cam + 12), (f32*)(cam + 16), (f32*)(cam + 20),
                                   *(int*)(cam + 48));
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

void CameraModeStatic_copyToCurrent_nop(void);

void CameraModeDebug_free(void)
{
    mm_free(gCamDebugState);
    gCamDebugState = 0;
}

void CameraModeStatic_free(void);
