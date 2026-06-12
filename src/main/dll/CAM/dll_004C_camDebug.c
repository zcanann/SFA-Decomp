#include "main/camera_object.h"
#include "main/dll/CAM/camclimb_state.h"
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/game_object.h"
#include "main/object_transform.h"

extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern float mathCosf(float x);
extern void Rcp_DisableBlurFilter(void);
extern void memset(void* dst, int val, int size);

extern CameraModeClimbState* lbl_803DD578;
extern CameraModeNpcSpeakState* lbl_803DD584;

extern f32 lbl_803E19B8;
extern f32 lbl_803E19BC;
extern f32 lbl_803E19C0;
extern f32 lbl_803E19C4;
extern f32 lbl_803E19C8;
extern f32 lbl_803E19D0;
extern f32 lbl_803E19D4;
extern f32 lbl_803E19D8;
extern f32 lbl_803E19DC;

void CameraModeClimb_init(undefined4 arg1, int mode, s8* args);

void CameraModeClimb_release(void);

void CameraModeClimb_initialise(void);

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

void CameraModeNpcSpeak_copyToCurrent_nop(void);

void CameraModeNpcSpeak_free(void);
