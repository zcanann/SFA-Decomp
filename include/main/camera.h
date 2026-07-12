#ifndef MAIN_CAMERA_H_
#define MAIN_CAMERA_H_

#include "global.h"
#include "main/object_transform.h"

typedef struct _GXRenderModeObj GXRenderModeObj;

typedef struct CameraViewSlot {
    s16 yaw;
    s16 pitch;
    s16 roll;
    u8 pad06[6];
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0x14];
    f32 shakeMagnitude;
    f32 shakeMagnitudeTarget;
    f32 shakeDuration;
    f32 shakeTimer;
    f32 shakeFalloff;
    u8 pad40[0x1C];
    s8 shakeFlipTimer;
    s8 shakeActive;
    u8 pad5E[2];
} CameraViewSlot;

typedef struct CameraMatrixTransform {
    s16 pitch;
    s16 yaw;
    s16 roll;
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} CameraMatrixTransform;

extern CameraViewSlot gCameraShakeSlots[];
extern GXRenderModeObj* gRenderModeObj;
extern f32 gCameraDefaultModelMatrix[16];
extern u8 lbl_80338090[];

void Obj_RotateLocalOffsetByYaw(f32* local, f32* out, s8 yawIndex);

f32* Camera_GetViewRotationMatrix(void);
f32* Camera_GetInverseViewRotationMatrix(void);
f32* Camera_GetViewMatrix(void);
f32* Camera_GetInverseViewMatrix(void);
void* Camera_GetCurrentViewSlot(void);
u8 CameraShake_IsActive(void);
void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff);
void CameraShake_SetAllMagnitudes(f32 magnitude);
void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 magnitude);
void Camera_LoadModelViewMatrix(void* unused0, void* unused1, CameraViewSlot* transform, f32 scale, f32* matrix);
void Camera_NdcToScreen(f32 ndcX, f32 ndcY, f32 ndcZ, s32* outX, s32* outY, s32* outZ);
void Camera_ProjectWorldPoint(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, f32* outViewZ);
void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 offset, f32* outX, f32* outY, f32* outZ);
void Camera_ProjectWorldSphere(f32 x, f32 y, f32 z, f32 radius, f32* outX, f32* outY, f32* outZ, f32* outRadiusX,
                               f32* outRadiusY, f32* outRadiusZ);
void Camera_ApplyCurrentViewport(void* viewportArg);
void Camera_UpdateProjection(void* viewportArg);
void Camera_GetCurrentViewport(s32* outX, s32* outY, u32* outHeight, s32* outWidth);
void Camera_SetCurrentViewIndex(int index);
f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
void Camera_SetCurrentViewRotation(int yaw, int pitch, int roll);
void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
void Camera_UpdateViewMatrices(void);
void Camera_ApplyFullViewport(void);
u8 Camera_IsViewYOffsetEnabled(void);
void Camera_DisableViewYOffset(void);
void Camera_EnableViewYOffset(void);
s16 Camera_GetViewportYOffset(void);
void Camera_SetViewportYOffset(s16 yOffset);
f32* Camera_GetProjectionMatrix(void);
void Camera_RebuildProjectionMatrix(void);
f32 Camera_GetFarPlane(void);
void Camera_SetFarPlane(f32 farPlane, int transitionFrames);
f32 Camera_GetNearPlane(void);
f32 Camera_GetAspectRatio(void);
void Camera_SetAspectRatio(f32 aspectRatio);
f32 Camera_GetFovY(void);
void Camera_SetFovY(f32 fovY);
void Camera_InitState(void);


#endif /* MAIN_CAMERA_H_ */
