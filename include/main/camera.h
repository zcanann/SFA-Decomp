#ifndef MAIN_CAMERA_H_
#define MAIN_CAMERA_H_

#include "global.h"
#include "main/object_transform.h"

f32 *Camera_GetViewMatrix(void);
f32 *Camera_GetViewRotationMatrix(void);
void *Camera_GetCurrentViewSlot(void);
void Obj_RotateLocalOffsetByYaw(f32 *local, f32 *out, u8 yawIndex);

f32 Camera_GetFarPlane(void);
f32 Camera_GetFovY(void);
f32 Camera_GetNearPlane(void);
f32* Camera_GetInverseViewRotationMatrix(void);
int Camera_IsViewYOffsetEnabled(void);
void Camera_ApplyFullViewport(void);
void Camera_DisableViewYOffset(void);
void Camera_EnableViewYOffset(void);
void Camera_RebuildProjectionMatrix(void);
void Camera_UpdateViewMatrices(void);
f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
void CameraShake_SetAllMagnitudes(f32 magnitude);
void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff);
void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 offset, f32* outX, f32* outY, f32* outZ);
void Camera_ProjectWorldSphere(f32 x, f32 y, f32 z, f32 radius, f32* outX, f32* outY, f32* outZ, f32* outRadiusX,
                               f32* outRadiusY, f32* outRadiusZ);
void Camera_SetAspectRatio(f32 aspectRatio);
void Camera_SetCurrentViewIndex(int index);
void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
void Camera_SetCurrentViewRotation(int pitch, int yaw, int roll);
void Camera_SetFovY(f32 fovY);
void Camera_UpdateProjection(int a, int b);

#endif /* MAIN_CAMERA_H_ */
