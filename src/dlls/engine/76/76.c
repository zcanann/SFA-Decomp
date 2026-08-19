/*
 * DLL 76 / 0x4C.
 */
#include "main/dll/dll_004C_cameramodefixed.h"

#include "main/object_transform.h"

void CameraModeFixed_copyToCurrent(void) {
}

void CameraModeFixed_free(void) {
}

void CameraModeFixed_update(void) {
}

void CameraModeFixed_init(CameraObject* camera, int unused, const CameraModeFixedPose* pose) {
    if (pose == NULL) {
        return;
    }

    camera->anim.worldPosX = pose->worldPosition.x;
    camera->anim.worldPosY = pose->worldPosition.y;
    camera->anim.worldPosZ = pose->worldPosition.z;
    Obj_TransformWorldPointToLocal(pose->worldPosition.x, pose->worldPosition.y, pose->worldPosition.z,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   camera->anim.parent);
    camera->anim.rotX = pose->cameraRotation.rotX;
    camera->anim.rotY = pose->cameraRotation.rotY;
    camera->anim.rotZ = pose->cameraRotation.rotZ;
    camera->fov = pose->fov;
}

void CameraModeFixed_release(void) {
}

void CameraModeFixed_initialise(void) {
}

CameraModeFixedDescriptor gCameraModeFixedDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeFixed_initialise,
    CameraModeFixed_release,
    NULL,
    CameraModeFixed_init,
    CameraModeFixed_update,
    CameraModeFixed_free,
    CameraModeFixed_copyToCurrent,
    NULL,
};
