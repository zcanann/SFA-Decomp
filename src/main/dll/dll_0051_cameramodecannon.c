/*
 * DLL 0x0051 - camera mode: cannon [8010DB7C-8010DD58)
 *
 * Camera mode used when the player is riding/aiming the cannon. A single
 * CameraModeCannonState (lbl_803DD5A0) is lazily mmAlloc'd by _init and
 * holds the followed target GameObject; _free releases it.
 *
 * Each frame _update aims the camera at the target: it eases the camera
 * yaw (rotX) toward the target's facing, corrected by the target model's
 * packed angle, then orbits the camera around the target on the XZ plane
 * at a fixed radius (lbl_803E1AE4) with a fixed height offset (lbl_803E1AF0).
 * The remaining entry points (release/initialise and the *_nop stubs) are
 * empty mode-table slots shared with the sibling camera-mode DLLs.
 */
#include "main/mm.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camera_mode_cannon_state.h"
#include "main/dll/fx_800944A0_shared.h"



extern s16* objModelGetVecFn_800395d8(int obj, int idx);
extern CameraModeCannonState* lbl_803DD5A0;
extern f32 lbl_803E1AE0; /* easing divisor */
extern f32 lbl_803E1AE4; /* orbit radius */
extern f32 lbl_803E1AE8; /* angle scale */
extern f32 lbl_803E1AEC; /* angle divisor */
extern f32 lbl_803E1AF0; /* height offset */

void CameraModeCannon_copyToCurrent_nop(void)
{
}

void CameraModeCannon_release(void)
{
}

void CameraModeCannon_initialise(void)
{
}

void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void CameraModeCannon_init(int* p1, int unused, int* p3)
{
    CameraObject* camera = (CameraObject*)p1;

    if (lbl_803DD5A0 == NULL)
    {
        lbl_803DD5A0 = (CameraModeCannonState*)mmAlloc(sizeof(CameraModeCannonState), 15, 0);
    }
    if (p3 != NULL)
    {
        lbl_803DD5A0->target = (GameObject*)*p3;
    }
    else
    {
        lbl_803DD5A0->target = NULL;
    }
    camera->anim.rotY = 2800; /* ~154 deg: initial camera yaw for cannon mode */
}

void CameraModeCannon_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5A0);
    lbl_803DD5A0 = NULL;
}

void CameraModeCannon_update(u8* obj)
{
    CameraObject* camera = (CameraObject*)obj;
    s16* vec;
    s16 yaw;
    s16 delta;

    vec = objModelGetVecFn_800395d8((int)lbl_803DD5A0->target, 0);
    if (lbl_803DD5A0->target == NULL)
    {
        return;
    }
    yaw = camera->anim.rotX;
    delta = (s16)((0x8000 - lbl_803DD5A0->target->anim.rotX) - vec[1] - yaw);
    camera->anim.rotX = (f32)(s32)yaw + (f32)(s32)delta / lbl_803E1AE0;
    camera->anim.localPosX =
        lbl_803DD5A0->target->anim.localPosX -
        lbl_803E1AE4 * mathSinf(lbl_803E1AE8 * (f32)(s32)(-camera->anim.rotX) / lbl_803E1AEC);
    camera->anim.localPosY = lbl_803E1AF0 + lbl_803DD5A0->target->anim.localPosY;
    camera->anim.localPosZ =
        lbl_803DD5A0->target->anim.localPosZ -
        lbl_803E1AE4 * mathCosf(lbl_803E1AE8 * (f32)(s32)(-camera->anim.rotX) / lbl_803E1AEC);
}
