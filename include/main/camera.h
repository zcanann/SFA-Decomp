#ifndef MAIN_CAMERA_H_
#define MAIN_CAMERA_H_

#include "global.h"
#include "main/camera_shake_api.h"
#include "main/vec_types.h"
#include "main/vecmath.h"

#define CAMERA_COUNT 12
#define OBJECT_TRANSFORM_MATRIX_COUNT 30

typedef struct GameObject GameObject;

typedef f32 CameraMatrix[16];
STATIC_ASSERT(sizeof(CameraMatrix) == 0x40);

typedef f32 CameraProjectionMatrix[4][4];
STATIC_ASSERT(sizeof(CameraProjectionMatrix) == 0x40);

typedef struct Camera {
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 flags;
    f32 scale;
    union {
        struct {
            f32 x;
            f32 y;
            f32 z;
        };
        Vec3f position;
    };
    f32 fovY;
    u8 pad1C[4];
    Vec3f velocity;
    f32 shakeOffsetY;
    f32 shakeAmplitude;
    f32 shakeFrequency;
    f32 shakeTime;
    f32 shakeDamping;
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
    u16 blockIndex;
    u16 unk58;
    s16 shakePitchOffset; /* Pitch delta contributed by camera shake. */
    s8 shakeCooldown;
    s8 shakeMode; /* -1: inactive, 0: bouncing offset, 1: dampened oscillation. */
    u8 pad5E[2];
} Camera;

STATIC_ASSERT(offsetof(Camera, flags) == 0x6);
STATIC_ASSERT(offsetof(Camera, scale) == 0x8);
STATIC_ASSERT(offsetof(Camera, fovY) == 0x18);
STATIC_ASSERT(offsetof(Camera, velocity) == 0x20);
STATIC_ASSERT(offsetof(Camera, shakeOffsetY) == 0x2C);
STATIC_ASSERT(offsetof(Camera, shakeAmplitude) == 0x30);
STATIC_ASSERT(offsetof(Camera, shakeFrequency) == 0x34);
STATIC_ASSERT(offsetof(Camera, shakeTime) == 0x38);
STATIC_ASSERT(offsetof(Camera, shakeDamping) == 0x3C);
STATIC_ASSERT(offsetof(Camera, parentObject) == 0x40);
STATIC_ASSERT(offsetof(Camera, blockIndex) == 0x56);
STATIC_ASSERT(offsetof(Camera, shakePitchOffset) == 0x5A);
STATIC_ASSERT(offsetof(Camera, shakeCooldown) == 0x5C);
STATIC_ASSERT(offsetof(Camera, shakeMode) == 0x5D);
STATIC_ASSERT(sizeof(Camera) == 0x60);

typedef struct CameraViewport {
    s32 x1;
    s32 y1;
    s32 x2;
    s32 y2;
    s32 posX;
    s32 posY;
    s32 width;
    s32 height;
    s32 scissorX1;
    s32 scissorY1;
    s32 scissorX2;
    s32 scissorY2;
    s32 flags;
} CameraViewport;

STATIC_ASSERT(offsetof(CameraViewport, scissorX1) == 0x20);
STATIC_ASSERT(offsetof(CameraViewport, scissorY1) == 0x24);
STATIC_ASSERT(offsetof(CameraViewport, scissorX2) == 0x28);
STATIC_ASSERT(offsetof(CameraViewport, scissorY2) == 0x2C);
STATIC_ASSERT(offsetof(CameraViewport, flags) == 0x30);
STATIC_ASSERT(sizeof(CameraViewport) == 0x34);

typedef struct CameraViewportTransform {
    s16 scaleX;
    s16 scaleY;
    s16 scaleZ;
    s16 scaleW;
    s16 translateX;
    s16 translateY;
    s16 translateZ;
    s16 translateW;
} CameraViewportTransform;

STATIC_ASSERT(offsetof(CameraViewportTransform, scaleX) == 0x0);
STATIC_ASSERT(offsetof(CameraViewportTransform, scaleY) == 0x2);
STATIC_ASSERT(offsetof(CameraViewportTransform, scaleZ) == 0x4);
STATIC_ASSERT(offsetof(CameraViewportTransform, translateX) == 0x8);
STATIC_ASSERT(offsetof(CameraViewportTransform, translateY) == 0xA);
STATIC_ASSERT(offsetof(CameraViewportTransform, translateZ) == 0xC);
STATIC_ASSERT(sizeof(CameraViewportTransform) == 0x10);

extern Camera gCameras[CAMERA_COUNT];
extern CameraViewport gCameraViewports[4];
extern CameraViewportTransform gCameraViewportTransforms[20];
extern CameraMatrix gCameraDefaultModelMatrix;
extern CameraMatrix gCameraWorldMatrix;
extern s8 gObjTransformMatrixSlot;
extern CameraMatrix gObjInverseYawTransformMatrices[OBJECT_TRANSFORM_MATRIX_COUNT];
extern CameraMatrix gObjYawTransformMatrices[OBJECT_TRANSFORM_MATRIX_COUNT];
extern CameraMatrix gCameraViewRotationMatrix;
extern CameraMatrix gCameraInverseViewRotationMatrix;
extern CameraMatrix gCameraViewMatrix;
extern CameraMatrix gCameraInverseViewMatrix;
extern u8 gCameraCurrentViewIndex;
extern s16 cameraViewportYOffset;
extern s16 gCameraViewportYOffset;
extern CameraProjectionMatrix gCameraProjectionMatrix;
extern f32 gCameraModelViewMatrix[3][4];
extern f32 gCameraLightPerspectiveMatrix[3][4];
extern f32 gCameraLightPerspectiveFlipYMatrix[3][4];
extern f32 gCameraLightPerspectiveScaledMatrix[3][4];
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
extern f32 gCameraEffectViewportFarZ;
extern u32 gViewportJitterField;
extern u16 gCameraPerspectiveNorm;

void Obj_RotateLocalOffsetByYaw(f32* local, f32* out, s8 yawIndex);

f32* Camera_GetViewRotationMatrix(void);
f32* Camera_GetInverseViewRotationMatrix(void);
f32* Camera_GetViewMatrix(void);
f32* Camera_GetInverseViewMatrix(void);
Camera* Camera_GetCurrent(void);
u8 CameraShake_IsActive(void);
void Camera_LoadModelViewMatrix(int unusedDisplayList, int unusedMatrixList, MatrixTransform* transform, f32 yScale,
                                f32 unusedOffsetY, f32* outMatrix);
void Camera_UpdateForObject(Camera* camera);
void Obj_BuildTransformMatrices(GameObject* obj);
s32 Obj_BuildTransformMatrixSlot(GameObject* obj);
void Camera_ClipToScreen(f32 clipX, f32 clipY, f32 clipZ, s32* outX, s32* outY, s32* outZ);
void Camera_ProjectWorldPoint(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, f32* outViewZ);
void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 offset, f32* outX, f32* outY, f32* outZ);
void Camera_ProjectWorldSphere(f32 x, f32 y, f32 z, f32 radius, f32* outX, f32* outY, f32* outZ, f32* outRadiusX,
                               f32* outRadiusY, f32* outRadiusZ);
void Camera_ApplyCurrentViewport(void* viewportArg);
void Camera_UpdateProjection(void* viewportArg, int unused);
void Camera_GetFullViewportRect(s32* outLeft, s32* outTop, u32* outRight, s32* outBottom);
void Camera_SetCurrentViewIndex(int index);
f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
void Camera_SetCurrentViewRotation(int yaw, int pitch, int roll);
void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
void Camera_UpdateViewMatrices(void);
void Camera_ApplyFullViewport(void);
s16 Camera_GetViewportYOffset(void);
void Camera_SetViewportYOffset(s16 yOffset);
f32* Camera_GetProjectionMatrix(void);
void Camera_RebuildProjectionMatrix(void);
f32 Camera_GetFarPlane(void);
void Camera_SetFarPlane(f32 farPlane, int transitionFrames);
void Camera_ResetFarPlane(void);
f32 Camera_GetNearPlane(void);
f32 Camera_GetAspectRatio(void);
void Camera_SetAspectRatio(f32 aspectRatio);

extern f32 gStandardAspectRatio;
f32 Camera_GetFovY(void);
void Camera_SetFovY(f32 fovY);
void Camera_InitState(void);
f32* Camera_GetWorldMatrix(void);
s32 Angle_AddWrappedS16(s32 angle, s16* delta);
s32 Angle_SubWrappedS16(s32 angle, s16* delta);
void Camera_SetupFullscreenViewport(void* viewportArg);
void Camera_UpdateShakeAndFarPlane(void);
void Camera_ApplyEffectDepthViewport(void);
void Camera_ApplyTransparentViewport(void);
void Camera_ApplyDecalViewport(void);
u16 Camera_GetCurrentViewPitch(void);
u16 Camera_GetCurrentViewYaw(void);

#endif /* MAIN_CAMERA_H_ */
