#ifndef MAIN_CAMERA_H_
#define MAIN_CAMERA_H_

#include "global.h"
#include "main/camera_shake_api.h"
#include "main/vec_types.h"
#include "main/vecmath.h"

typedef struct _GXRenderModeObj GXRenderModeObj;
typedef struct GameObject GameObject;

typedef struct CameraViewSlot {
    s16 yaw;
    s16 pitch;
    s16 roll;
    u8 pad06[6];
    union {
        struct {
            f32 x;
            f32 y;
            f32 z;
        };
        Vec3f position;
    };
    u8 pad18[0x14];
    f32 shakeMagnitude;
    f32 shakeMagnitudeTarget;
    f32 shakeDuration;
    f32 shakeTimer;
    f32 shakeFalloff;
    GameObject* parentObject;
    union {
        struct {
            f32 worldX;
            f32 worldY;
            f32 worldZ;
        };
        Vec3f worldPosition;
    };
    s16 worldYaw;
    s16 worldPitch;
    s16 worldRoll;
    u8 pad56[6];
    s8 shakeFlipTimer;
    s8 shakeActive;
    u8 pad5E[2];
} CameraViewSlot;

extern CameraViewSlot gCameraShakeSlots[];
extern GXRenderModeObj* gRenderModeObj;
extern f32 gCameraDefaultModelMatrix[16];
extern f32 lbl_80338090[64];
extern f32 lbl_803DE5F0;
extern f32 gCameraShakeMagnitudeDecay;
extern f32 gCameraPi;
extern f32 lbl_803DE5FC;
extern f32 lbl_803DE600;
extern f32 gCameraShakeStopThreshold;
extern f32 gCameraShakeStopThresholdNeg;
extern f32 lbl_803DE610;
extern f32 gCameraDepth24BitMax;
extern f32 lbl_803DE624;
extern s8 gObjTransformMatrixSlot;
extern f32 gObjInverseYawTransformMatrices[][16];
extern f32 gObjYawTransformMatrices[][16];
extern f32 gCameraViewRotationMatrix[16];
extern f32 gCameraInverseViewRotationMatrix[16];
extern f32 gCameraViewMatrix[16];
extern f32 gCameraInverseViewMatrix[16];
extern u8 gCameraCurrentViewIndex;
extern u8 cameraViewYOffsetEnabled;
extern s16 cameraViewportYOffset;
extern s16 gCameraViewportYOffset;
extern f32 gCameraProjectionMatrix[16];
extern f32 lbl_803967C0[3][4];
extern f32 lbl_803967F0[3][4];
extern f32 lbl_80396820[3][4];
extern f32 lbl_80396850[3][4];
extern f32 gCameraFarPlane;
extern f32 gCameraNearPlane;
extern f32 gCameraAspectRatio;
extern f32 gCameraFovY;
extern s32 gCameraProjectionMode;
extern s16 gCameraFarPlaneTransitionFramesLeft;
extern s16 gCameraFarPlaneTransitionFrames;
extern f32 gCameraFarPlaneTransitionTarget;
extern f32 gCameraFarPlaneTransitionStart;
extern f32 gCameraOrthoRight;
extern f32 gCameraOrthoLeft;
extern f32 gCameraOrthoBottom;
extern f32 gCameraOrthoTop;
extern f32 lbl_803DE60C;
extern f32 lbl_803DE628;
extern f32 lbl_803DE62C;
extern f32 lbl_803DE630;
extern f32 lbl_803DE640;
extern f32 lbl_803DE644;
extern f32 lbl_803DE648;
extern f32 gCameraDefaultFarPlane;
extern f32 gCameraDefaultPosition;
extern f32 lbl_803DE65C;
extern f32 lbl_803DE670;
extern f32 lbl_803DE678;
extern f32 lbl_803DE694;
extern f32 lbl_803DE698;
extern f32 lbl_803DB26C;
extern s16 gCameraViewportScreenParams[];
extern u32 lbl_803DCCBC;
extern s16 lbl_803DC88A;
extern u8 gCameraViewportEntries[];

void Obj_RotateLocalOffsetByYaw(f32* local, f32* out, s8 yawIndex);

f32* Camera_GetViewRotationMatrix(void);
f32* Camera_GetInverseViewRotationMatrix(void);
f32* Camera_GetViewMatrix(void);
f32* Camera_GetInverseViewMatrix(void);
CameraViewSlot* Camera_GetCurrentViewSlot(void);
u8 CameraShake_IsActive(void);
void Camera_LoadModelViewMatrix(void* unused0, void* unused1, CameraViewSlot* transform, f32 scale, f32* matrix);
void Obj_UpdateWorldTransform(CameraViewSlot* view);
void Obj_BuildTransformMatricesForYaw(GameObject* obj, s32 yawIndex);
void Obj_BuildTransformMatrices(GameObject* obj);
s32 Obj_BuildTransformMatrixSlot(GameObject* obj);
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
f32* fn_8000E814(void);
s32 Angle_AddWrappedS16(s32 angle, s16* delta);
s32 Angle_SubWrappedS16(s32 angle, s16* delta);
void screenFn_8000e944(void* viewportArg);
void viewportEffectFn_8000e380(void);
void fn_8000F83C(void);
void fn_8000F8F8(void);
void fn_8000F9B4(void);
u16 fn_8000FA70(void);
u16 fn_8000FA90(void);


#endif /* MAIN_CAMERA_H_ */
