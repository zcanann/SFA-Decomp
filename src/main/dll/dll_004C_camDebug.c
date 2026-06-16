/*
 * camDebug (DLL 0x4C) - "fixed" camera mode.
 *
 * A static/debug camera mode object: most of its lifecycle hooks are
 * no-ops (copyToCurrent/free/update/release/init-pass). CameraModeFixed_init
 * snapshots a source camera into this one - copying world position,
 * deriving the local-space position relative to the source's parent, and
 * cloning the orientation and field of view - then holds that pose fixed.
 */
#include "main/camera_object.h"
#include "main/object_transform.h"

void CameraModeFixed_copyToCurrent_nop(void)
{
}

void CameraModeFixed_free_nop(void)
{
}

void CameraModeFixed_update(void)
{
}

void CameraModeFixed_init(CameraObject* camera, int unused, CameraObject* src)
{
    if (src != NULL)
    {
        camera->anim.worldPosX = src->anim.worldPosX;
        camera->anim.worldPosY = src->anim.worldPosY;
        camera->anim.worldPosZ = src->anim.worldPosZ;
        Obj_TransformWorldPointToLocal(src->anim.worldPosX, src->anim.worldPosY, src->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       (u32)camera->anim.parent);
        camera->anim.rotX = src->anim.rotX;
        camera->anim.rotY = src->anim.rotY;
        camera->anim.rotZ = src->anim.rotZ;
        camera->fov = src->fov;
    }
}

void CameraModeFixed_release(void)
{
}

void CameraModeFixed_initialise(void)
{
}
