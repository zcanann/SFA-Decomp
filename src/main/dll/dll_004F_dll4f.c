/* DLL 0x004F - Camera mode misc handler [0x8010F2F8-0x8010F540). */
#include "main/mm.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/curve.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camera_mode_4f_state.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"

CameraMode4FState* gCameraMode4FState;


#pragma scheduling off
#pragma peephole off
void dll_4F_func06_nop(void)
{
}

void dll_4F_func05(void)
{
    mm_free((void*)gCameraMode4FState);
    gCameraMode4FState = NULL;
}

void dll_4F_update(int* obj)
{
    CameraObject* camera;
    GameObject* target;
    f32 pts[4];
    f32 fz;
    f32 sn;
    f32 cs;
    s16 angle;

    camera = (CameraObject*)obj;
    pts[0] = 0.0f;
    pts[1] = 1.0f;
    pts[2] = 0.0f;
    pts[3] = 0.0f;
    fz = Curve_EvalHermiteValuesFirst(pts, gCameraMode4FState->blendProgress, NULL);
    angle = (s16)(0x8000 - ((GameObject*)camera->anim.targetObj)->anim.rotX);
    angle += (s32)(14560.0f * fz);
    target = (GameObject*)camera->anim.targetObj;
    {
        f32 t = (3.1415927f * (f32)(s32)angle) / 32768.0f;
        sn = mathCosf(t);
        cs = mathSinf(t);
    }
    camera->anim.localPosX = target->anim.worldPosX + (20.0f * sn - -10.0f * cs);
    camera->anim.localPosZ = target->anim.worldPosZ + (20.0f * cs + -10.0f * sn);
    camera->anim.localPosY = (35.0f + target->anim.worldPosY) - 15.0f * fz;
    camera->anim.rotY = (s16)(0x11c6 - (s32)(35.0f * (182.0f * fz)));
    camera->anim.rotX = (s16)(angle + 0x1ffe);
    camera->anim.rotZ = 0;
    camera->letterboxTargetOffset = 0;
    camera->fov = 60.0f;
    gCameraMode4FState->blendProgress += 0.005f * timeDelta;
    if (gCameraMode4FState->blendProgress > 1.0f)
    {
        gCameraMode4FState->blendProgress = 1.0f;
    }
}

void dll_4F_init(void)
{
    if (gCameraMode4FState == NULL)
    {
        gCameraMode4FState = (CameraMode4FState*)mmAlloc(sizeof(CameraMode4FState), 15, 0);
    }
    gCameraMode4FState->blendProgress = 0.0f;
}

void dll_4F_release_nop(void)
{
}

void dll_4F_initialise_nop(void)
{
}

u32 lbl_80319E38[12] = {0x00000000, 0x00000000, 0x00000000, 0x00060000,
        (u32)dll_4F_initialise_nop, (u32)dll_4F_release_nop,
        0x00000000, (u32)dll_4F_init, (u32)dll_4F_update,
        (u32)dll_4F_func05, (u32)dll_4F_func06_nop, 0x00000000};
