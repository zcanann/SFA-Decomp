#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camclimb_state.h"
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/object_transform.h"

extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern float mathCosf(float x);
extern void Rcp_DisableBlurFilter(void);
extern void memset(void *dst, int val, int size);

extern CameraModeClimbState *lbl_803DD578;
extern CameraModeNpcSpeakState *lbl_803DD584;

extern f32 lbl_803E19B8;
extern f32 lbl_803E19BC;
extern f32 lbl_803E19C0;
extern f32 lbl_803E19C4;
extern f32 lbl_803E19C8;
extern f32 lbl_803E19D0;
extern f32 lbl_803E19D4;
extern f32 lbl_803E19D8;
extern f32 lbl_803E19DC;

void CameraModeClimb_init(undefined4 param_1, int param_2, s8 *param_3) {
    f32 local_58;
    f32 local_5c;
    f32 local_60;
    f32 local_64;
    f32 local_68;
    undefined4 local_28[8];
    undefined4 local_24[1];
    undefined4 local_20[1];
    undefined4 local_1c[1];
    int iVar2;

    if (lbl_803DD578 == NULL) {
        lbl_803DD578 = (CameraModeClimbState *)mmAlloc(sizeof(CameraModeClimbState), 0xf, 0);
    }
    switch (param_2) {
    case 2:
        lbl_803DD578->startRelativePosition = lbl_803DD578->relativePosition;
        lbl_803DD578->startMinHeight = lbl_803DD578->minHeight;
        lbl_803DD578->startMaxHeight = lbl_803DD578->maxHeight;
        lbl_803DD578->startDistance = lbl_803DD578->targetDistance;
        lbl_803DD578->targetRelativePosition = (s16)(lbl_803E19B8 * (f32)(s8)param_3[3]);
        lbl_803DD578->endMinHeight = (f32)(s8)param_3[5];
        lbl_803DD578->endMaxHeight = (f32)(s8)param_3[4];
        lbl_803DD578->endDistance = (f32)(s8)param_3[2];
        lbl_803DD578->transitionTimer = (s16)(s8)param_3[1];
        lbl_803DD578->transitionDuration = (s16)(s8)param_3[1];
        break;
    case 1:
    default:
        memset(lbl_803DD578, 0, sizeof(CameraModeClimbState));
        iVar2 = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        ((code)(*(undefined4 **)((undefined4 *)iVar2)[1])[8])(&local_58, &local_5c, &local_60, &local_64, &local_68);
        (*gCameraInterface)->getRelativePosition((f32)(u16)lbl_803DD578->relativePosition,
                                                 (int)param_1, (f32 *)local_28,
                                                 (f32 *)local_24, (f32 *)local_20,
                                                 (f32 *)local_1c, 0);
        lbl_803DD578->startRelativePosition = (s16)local_68;
        lbl_803DD578->startMinHeight = local_60;
        lbl_803DD578->startMaxHeight = local_64;
        lbl_803DD578->startDistance = *(f32 *)local_1c;
        lbl_803DD578->targetRelativePosition = 30;
        lbl_803DD578->endMinHeight = lbl_803E19BC;
        lbl_803DD578->endMaxHeight = lbl_803E19C0;
        lbl_803DD578->endDistance = lbl_803E19C4 * (local_5c + local_58);
        lbl_803DD578->transitionTimer = 60;
        lbl_803DD578->transitionDuration = 60;
        lbl_803DD578->smoothedDistance = *(f32 *)local_1c;
        lbl_803DD578->heightAdjustRate = lbl_803E19C8;
        break;
    }
}

void CameraModeClimb_release(void) {}
void CameraModeClimb_initialise(void) {}
void CameraModeFixed_copyToCurrent_nop(void) {}
void CameraModeFixed_free_nop(void) {}
void CameraModeFixed_update(void) {}

void CameraModeFixed_init(CameraObject *camera, undefined4 param_2, CameraObject *src) {
    if (src != NULL) {
        camera->anim.worldPosX = src->anim.worldPosX;
        camera->anim.worldPosY = src->anim.worldPosY;
        camera->anim.worldPosZ = src->anim.worldPosZ;
        Obj_TransformWorldPointToLocal(src->anim.worldPosX, src->anim.worldPosY, src->anim.worldPosZ,
                     &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                     *(s32 *)&camera->anim.parent);
        camera->anim.rotX = src->anim.rotX;
        camera->anim.rotY = src->anim.rotY;
        camera->anim.rotZ = src->anim.rotZ;
        camera->fov = src->fov;
    }
}

void CameraModeFixed_release(void) {}
void CameraModeFixed_initialise(void) {}

void fn_8010DB7C(GameObject *target, f32 *outX, f32 *outY, f32 *outZ) {
    CameraModeNpcSpeakState *state = lbl_803DD584;
    f32 dx;
    f32 dz;
    f32 dist;
    u16 angle;
    f32 cosVal;
    f32 sinVal;

    dx = target->anim.worldPosX - state->anchorX;
    dz = target->anim.worldPosZ - state->anchorZ;
    dist = sqrtf(dz * dz + dx * dx);
    angle = (u16)getAngle(dx, dz);

    {
        f32 scale = state->anchorLerpScale;
        dx *= scale;
        dz *= scale;
    }
    dx += state->anchorX;
    dz += state->anchorZ;

    cosVal = mathSinf(lbl_803E19D0 * (f32)(s32)((angle & 0xFFFF) + state->orbitAngleOffset) / lbl_803E19D4);
    sinVal = mathCosf(lbl_803E19D0 * (f32)(s32)((angle & 0xFFFF) + state->orbitAngleOffset) / lbl_803E19D4);

    if (dist < state->minDistance) {
        dist = state->minDistance;
    }
    dist += state->distanceOffset;

    *outX = cosVal * dist + dx;
    *outY = (target->anim.worldPosY + state->targetHeightOffset) - lbl_803E19D8 * ((lbl_803E19DC + target->anim.worldPosY) - state->anchorY);
    *outZ = sinVal * dist + dz;
}

void CameraModeNpcSpeak_copyToCurrent_nop(void) {}

void CameraModeNpcSpeak_free(void) {
    mm_free(lbl_803DD584);
    lbl_803DD584 = 0;
    Rcp_DisableBlurFilter();
}
