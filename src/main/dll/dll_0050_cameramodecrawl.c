/*
 * cameramodecrawl (DLL 0x50) - the "crawl" camera mode.
 *
 * Owns the CameraModeCrawlState singleton (lbl_803DD598): allocates it on
 * init, frees it on shutdown, and on each update positions the camera behind
 * the target. The packed yaw is converted to radians via 3.1415927f/32768.0f
 * (pi numerator over 0x8000 denominator). With its own handler it
 * parks the camera at a fixed follow distance/height (13.0f/20.0f)
 * facing the target's yaw, eases rotX toward the target heading and pins
 * rotY to 2048; with the default handler
 * active it delegates positioning to the shared camera-interface entry and
 * forwards the result. copyToCurrent snapshots the target's transform into
 * the live camera. The camera position is finally pushed back to local space
 * via Obj_TransformWorldPointToLocal.
 *
 * The remaining entry points (release/initialise) are empty mode-table slots
 * shared with the sibling camera-mode DLLs.
 */
#include "main/mm.h"
#include "main/dll/CAM/cutCam.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/dll/CAM/camcrawl_state.h"
#include "string.h"
#include "main/dll/dll_80220608_shared.h"
#include "main/object_transform.h"

extern CameraModeCrawlState* lbl_803DD598;

#pragma scheduling off
#pragma peephole off

void CameraModeCrawl_copyToCurrent(void* param1, int param2)
{
    int obj;
    GameObject* target;
    int yaw;
    f32 c, s;
    f32 pos[3];

    if (param1 == NULL)
    {
        return;
    }
    obj = (int)(*gCameraInterface)->getCamera();
    target = (GameObject*)((CameraObject*)obj)->anim.targetObj;
    yaw = target->anim.rotX;

    if (param2 == 0)
    {
        c = mathSinf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
        s = mathCosf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
    }
    else
    {
        c = -mathSinf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
        s = -mathCosf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f);
    }
    {
        target->anim.rotX = getAngle(c, s);
    }
    camcontrol_getTargetPosition((CameraObject*)obj, &target->anim, pos, NULL);
    target->anim.rotX = yaw;
    {
        f32 p;
        p = pos[0];
        ((CameraObject*)obj)->anim.worldPosX = p;
        ((CameraObject*)obj)->probePosX = p;
        p = pos[1];
        ((CameraObject*)obj)->anim.worldPosY = p;
        ((CameraObject*)obj)->probePosY = p;
        p = pos[2];
        ((CameraObject*)obj)->anim.worldPosZ = p;
        ((CameraObject*)obj)->probePosZ = p;
    }
    Obj_TransformWorldPointToLocal(((CameraObject*)obj)->anim.worldPosX, ((CameraObject*)obj)->anim.worldPosY,
                                   ((CameraObject*)obj)->anim.worldPosZ,
                                   &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosY,
                                   &((GameObject*)obj)->anim.localPosZ,
                                   *(int*)&((CameraObject*)obj)->anim.parent);
    lbl_803DD598->flags.useDefaultHandler = 1;
}

void CameraModeCrawl_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD598);
    lbl_803DD598 = NULL;
}

void CameraModeCrawl_update(u8* obj)
{
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    int delta;
    f32 dx, outY, dz, outW;
    int other;

    if (target == NULL)
    {
        return;
    }
    if (lbl_803DD598->flags.useDefaultHandler == 0)
    {
        camera->anim.worldPosX =
            13.0f * mathSinf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f) +
            target->anim.worldPosX;
        camera->anim.worldPosZ =
            13.0f * mathCosf(3.1415927f * (f32)(s32)target->anim.rotX / 32768.0f) +
            target->anim.worldPosZ;
        camera->anim.worldPosY = 20.0f + target->anim.worldPosY;
        dx = camera->anim.localPosX - target->anim.worldPosX;
        dz = camera->anim.localPosZ - target->anim.worldPosZ;
        {
            int t = 0x8000 - (u16)getAngle(dx, dz);
            delta = t - (u16)camera->anim.rotX;
        }
        if (0x8000 < delta)
        {
            delta = delta - 0xffff;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xffff;
        }
        camera->anim.rotX = (s16)((f32)(s32)camera->anim.rotX +
                                  interpolate((f32)(s32)delta, 0.125f, timeDelta));
        camera->anim.rotX = (s16)(0x8000 - getAngle(dx, dz));
        camera->anim.rotY = 2048;
    }
    else
    {
        other = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        (*(void (**)(u8*, f32*, f32*, f32*, f32*, f32, int))(*(int*)gCameraInterface + 56))(
            obj, &dx, &outY, &dz, &outW, 35.0f, 0);
        {
            int t = 0x8000 - (u16)getAngle(dx, dz);
            delta = t - (u16)camera->anim.rotX;
        }
        if (0x8000 < delta)
        {
            delta = delta - 0xffff;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xffff;
        }
        camera->anim.rotX += delta;
        (*(void (**)(u8*, f32, f32))(*(int*)(*(int*)(other + 4)) + 24))(
            obj, target->anim.worldPosY, outW);
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

void CameraModeCrawl_init(void)
{
    if (lbl_803DD598 == NULL)
    {
        lbl_803DD598 = (CameraModeCrawlState*)mmAlloc(sizeof(CameraModeCrawlState), 15, 0);
        memset(lbl_803DD598, 0, sizeof(CameraModeCrawlState));
    }
}

void CameraModeCrawl_release(void)
{
}

void CameraModeCrawl_initialise(void)
{
}

/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */

/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */

/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */

/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */

/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */

/* EN v1.0 0x8011395C  size: 628b  Constrains a follow point against the
 * object's facing plane and returns the lateral offset of the result. */

/* EN v1.0 0x801147BC  size: 864b  Homes the object toward its target at the
 * given speed, snapping when close, easing yaw and pacing the walk anim. */
