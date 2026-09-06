/*
 * DLL 70 / 0x46 - debug camera mode.
 */
#include "main/dll/dll_0046_cameramodedebug.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/pad.h"
#include "game/objects/object.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"

CameraModeDebugState* gCameraModeDebugState;

void CameraModeDebug_copyToCurrent_nop(void) {
}

void CameraModeDebug_free(void) {
    mm_free(gCameraModeDebugState);
    gCameraModeDebugState = NULL;
}

void CameraModeDebug_update(CameraObject* camera) {
    GameObject* target;
    u16 held;
    f32 move;
    f32 absMove;
    f32 absVel;
    f32 factor;
    f32 radius;

    move = 0.0f;
    target = (GameObject*)camera->anim.targetObj;
    held = getButtonsHeld(0);
    if (((u16)getButtonsJustPressed(0) & PAD_BUTTON_RIGHT) != 0) {
        (*gCameraInterface)->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, 0, 0xff);
        return;
    }
    if ((held & PAD_BUTTON_UP) != 0) {
        move = -0.04f * gCameraModeDebugState->orbitRadius;
    }
    if ((held & PAD_BUTTON_DOWN) != 0) {
        move = 0.04f * gCameraModeDebugState->orbitRadius;
    }
    absMove = (move < 0.0f) ? -move : move;
    {
        CameraModeDebugState* state = gCameraModeDebugState;
        f32 vel = state->radiusVelocity;
        absVel = (vel < 0.0f) ? -vel : vel;
        factor = (absVel > absMove) ? 0.3f : 0.08f;
        state->radiusVelocity = factor * (move - vel) + state->radiusVelocity;
    }
    gCameraModeDebugState->orbitRadius += gCameraModeDebugState->radiusVelocity;
    if (gCameraModeDebugState->orbitRadius < 20.0f) {
        gCameraModeDebugState->orbitRadius = 20.0f;
    }
    if (gCameraModeDebugState->orbitRadius > 2000.0f) {
        gCameraModeDebugState->orbitRadius = 2000.0f;
    }
    {
        u16 dx = (u16)(padGetCX(0) * 3);
        u16 dy = (u16)(padGetCY(0) * 3);
        camera->anim.rotX = (s16)(camera->anim.rotX - dx);
        camera->anim.rotY = (s16)(camera->anim.rotY + dy);
    }
    {
        f32 cosYaw = mathSinf(3.1415927f * (f32)(s32)(camera->anim.rotX - 0x4000) / 32768.0f);
        f32 sinYaw = mathCosf(3.1415927f * (f32)(s32)(camera->anim.rotX - 0x4000) / 32768.0f);
        f32 cosPitch = mathCosf(3.1415927f * (f32)(s32)camera->anim.rotY / 32768.0f);
        f32 sinPitch = mathSinf(3.1415927f * (f32)(s32)camera->anim.rotY / 32768.0f);
        f32 vy, h, px;
        radius = gCameraModeDebugState->orbitRadius;
        vy = radius * sinPitch;
        h = radius * cosPitch;
        px = h * sinYaw;
        h *= cosYaw;
        camera->anim.worldPosX = target->anim.worldPosX + px;
        {
            f32 base28 = 20.0f + target->anim.worldPosY;
            camera->anim.worldPosY = base28 + vy;
        }
        camera->anim.worldPosZ = target->anim.worldPosZ + h;
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

void CameraModeDebug_init(void) {
    if (gCameraModeDebugState == NULL) {
        gCameraModeDebugState = (CameraModeDebugState*)mmAlloc(sizeof(CameraModeDebugState), 0xf, 0);
    }
    gCameraModeDebugState->orbitRadius = 50.0f;
    gCameraModeDebugState->radiusVelocity = 0.0f;
    return;
}

void CameraModeDebug_release_nop(void) {
}

void CameraModeDebug_initialise_nop(void) {
}

CameraModeDebugDescriptor gCameraModeDebugDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeDebug_initialise_nop,
    CameraModeDebug_release_nop,
    NULL,
    CameraModeDebug_init,
    CameraModeDebug_update,
    CameraModeDebug_free,
    CameraModeDebug_copyToCurrent_nop,
    NULL,
};
