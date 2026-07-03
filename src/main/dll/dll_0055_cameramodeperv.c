/*
 * cameramodeperv (DLL 0x0055) - the "perv" (peering/peeking) camera mode
 * handlers [0x80110C80-0x80110E30).
 *
 * The mode keeps a single shared CameraModePervState (lbl_803DD5C8) holding a
 * countdown timer and a cached camera Y. init() allocates the state on first
 * use, seeds the timer and the camera Y from the target object's world Y; free
 * releases it. update() ticks the timer down (clamped to a floor), then places
 * the camera a fixed radius behind the target on the X/Z plane using the
 * target's facing angle (rotX) and pins the camera pitch (rotY = -0x4000).
 *
 * The remaining vtable slots (copyToCurrent / release / initialise) are empty
 * no-op stubs.
 */
#include "main/mm.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camperv_state.h"
#include "main/game_object.h"
#include "main/dll/dll_80220608_shared.h"
extern CameraModePervState* lbl_803DD5C8;
extern f32 lbl_803E1B98;
extern f32 lbl_803E1B9C;
extern f32 lbl_803E1B78;
extern f32 lbl_803E1B7C;
extern f32 lbl_803E1B80;
extern f32 lbl_803E1B84;
extern f32 lbl_803E1B88;




void CameraModePerv_release(void)
{
}

void CameraModePerv_initialise(void)
{
}

void CameraModePerv_copyToCurrent(void)
{
}

void CameraModePerv_init(int* obj)
{
    CameraObject* camera = (CameraObject*)obj;

    if (lbl_803DD5C8 == NULL)
    {
        lbl_803DD5C8 = (CameraModePervState*)mmAlloc(sizeof(CameraModePervState), 15, 0);
    }
    lbl_803DD5C8->timer = lbl_803E1B98;
    lbl_803DD5C8->cameraY = ((GameObject*)camera->anim.targetObj)->anim.worldPosY - lbl_803E1B9C;
}

#pragma opt_common_subs off
#pragma opt_common_subs reset

void CameraModePerv_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5C8);
    lbl_803DD5C8 = NULL;
}

#pragma dont_inline on
#pragma dont_inline reset

void CameraModePerv_update(u8* obj)
{
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;

    lbl_803DD5C8->timer -= lbl_803E1B78 * timeDelta;
    if (lbl_803DD5C8->timer < *(f32*)&lbl_803E1B7C)
    {
        lbl_803DD5C8->timer = lbl_803E1B7C;
    }
    camera->anim.localPosX =
        target->anim.worldPosX -
        lbl_803E1B80 * mathSinf(lbl_803E1B84 * (f32)(s32)target->anim.rotX / lbl_803E1B88);
    camera->anim.localPosY = lbl_803DD5C8->cameraY;
    camera->anim.localPosZ =
        target->anim.worldPosZ -
        lbl_803E1B80 * mathCosf(lbl_803E1B84 * (f32)(s32)target->anim.rotX / lbl_803E1B88);
    camera->anim.rotX = 0;
    camera->anim.rotY = -0x4000;
    camera->anim.rotZ = 0;
}
