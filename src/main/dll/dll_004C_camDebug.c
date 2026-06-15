#include "main/camera_object.h"
#include "main/game_object.h"
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

void CameraModeFixed_init(CameraObject* camera, undefined4 param_2, CameraObject* src)
{
    if (src != NULL)
    {
        camera->anim.worldPosX = src->anim.worldPosX;
        camera->anim.worldPosY = src->anim.worldPosY;
        camera->anim.worldPosZ = src->anim.worldPosZ;
        Obj_TransformWorldPointToLocal(src->anim.worldPosX, src->anim.worldPosY, src->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       *(s32*)&camera->anim.parent);
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

void fn_8010DB7C(GameObject* target, f32* outX, f32* outY, f32* outZ);


