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
 * at a fixed radius (60.0f) with a fixed height offset (80.0f).
 * The remaining entry points (release/initialise and the *_nop stub) are
 * empty mode-table slots shared with the sibling camera-mode DLLs.
 */
#include "main/mm.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camera_mode_cannon_state.h"
#include "main/dll/fx_800944A0_shared.h"



extern s16* objModelGetVecFn_800395d8(int obj, int idx);
extern CameraModeCannonState* lbl_803DD5A0;

void CameraModeCannon_copyToCurrent_nop(void)
{
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
    camera->anim.rotX = (f32)(s32)yaw + (f32)(s32)delta / 5.0f;
    camera->anim.localPosX =
        lbl_803DD5A0->target->anim.localPosX -
        60.0f * mathSinf(3.1415927f * (f32)(s32)(-camera->anim.rotX) / 32768.0f);
    camera->anim.localPosY = 80.0f + lbl_803DD5A0->target->anim.localPosY;
    camera->anim.localPosZ =
        lbl_803DD5A0->target->anim.localPosZ -
        60.0f * mathCosf(3.1415927f * (f32)(s32)(-camera->anim.rotX) / 32768.0f);
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

void CameraModeCannon_release(void)
{
}

void CameraModeCannon_initialise(void)
{
}
