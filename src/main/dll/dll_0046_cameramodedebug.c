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

/* pad.h declares getButtonsJustPressed as u32; the u16 override in
   CameraModeDebug_update is load-bearing for the mask comparison. */
extern u32 getButtonsHeld(int port);
extern char padGetCX(int port);
extern char padGetCY(int port);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

/* camera mode id to restore on B-press exit */
#define CAMCONTROL_ACTION_DEFAULT 0x42

extern CameraModeDebugState* lbl_803DD550;
extern f32 lbl_803E1840;
extern f32 lbl_803E1844;
extern f32 lbl_803E1848;
extern f32 lbl_803E184C;
extern f32 lbl_803E1850;
extern f32 lbl_803E1854;
extern f32 lbl_803E1858;
extern f32 lbl_803E185C;
extern f32 lbl_803E1860;
extern f32 lbl_803E1870;

void CameraModeDebug_update(short* camObj)
{
    extern u16 getButtonsJustPressed(int port); /* u16 override: & 2 must produce cmplwi, not cmpwi */
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
        move = lbl_803E1844 * lbl_803DD550->orbitRadius;
    }
    if ((held & 4) != 0)
    {
        move = lbl_803E1848 * lbl_803DD550->orbitRadius;
    }
    absMove = (move < lbl_803E1840) ? -move : move;
    absVel = (lbl_803DD550->radiusVelocity < lbl_803E1840)
                 ? -lbl_803DD550->radiusVelocity
                 : lbl_803DD550->radiusVelocity;
    factor = lbl_803E1850;
    if (absMove < absVel)
    {
        factor = lbl_803E184C;
    }
    lbl_803DD550->radiusVelocity = factor * (move - lbl_803DD550->radiusVelocity) + lbl_803DD550->radiusVelocity;
    lbl_803DD550->orbitRadius = lbl_803DD550->orbitRadius + lbl_803DD550->radiusVelocity;
    if (lbl_803DD550->orbitRadius < lbl_803E1854)
    {
        lbl_803DD550->orbitRadius = lbl_803E1854;
    }
    if (lbl_803DD550->orbitRadius > lbl_803E1858)
    {
        lbl_803DD550->orbitRadius = lbl_803E1858;
    }
    {
        u16 dx = (u16)((s8)padGetCX(0) * 3);
        u16 dy = (u16)((s8)padGetCY(0) * 3);
        *(s16*)cam = (s16)(*(s16*)cam - dx);
        *(s16*)(cam + 2) = (s16)(*(s16*)(cam + 2) + dy);
    }
    {
        f32 cosYaw = mathSinf(lbl_803E185C * (f32)(s32)(*(s16*)cam - 0x4000) / lbl_803E1860);
        f32 sinYaw = mathCosf(lbl_803E185C * (f32)(s32)(*(s16*)cam - 0x4000) / lbl_803E1860);
        f32 sinPitch = mathCosf(lbl_803E185C * (f32)(s32)(*(s16*)(cam + 2) - 0x4000) / lbl_803E1860);
        f32 cosPitch = mathSinf(lbl_803E185C * (f32)(s32)(*(s16*)(cam + 2) - 0x4000) / lbl_803E1860);
        radius = lbl_803DD550->orbitRadius;
        *(f32*)(cam + 24) = *(f32*)(state + 24) + radius * sinPitch * sinYaw;
        *(f32*)(cam + 28) = lbl_803E1854 + *(f32*)(state + 28) + radius * cosPitch;
        *(f32*)(cam + 32) = *(f32*)(state + 32) + radius * sinPitch * cosYaw;
    }
    Obj_TransformWorldPointToLocal(*(f32*)(cam + 24), *(f32*)(cam + 28), *(f32*)(cam + 32),
                                   (f32*)(cam + 12), (f32*)(cam + 16), (f32*)(cam + 20),
                                   *(int*)(cam + 48));
}

void CameraModeDebug_init(void)
{
    if (lbl_803DD550 == NULL)
    {
        lbl_803DD550 = (CameraModeDebugState*)mmAlloc(sizeof(CameraModeDebugState), 0xf, 0);
    }
    lbl_803DD550->orbitRadius = lbl_803E1870;
    lbl_803DD550->radiusVelocity = lbl_803E1840;
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
    mm_free(lbl_803DD550);
    lbl_803DD550 = 0;
}

void CameraModeStatic_free(void);
