#include "main/camera.h"
#include "main/object_transform.h"
#include "main/pi_dolphin.h"
#include "main/frame_timing.h"
#include "game/objects/object.h"
#include "main/pause_menu_api.h"
#include "main/shader_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/gx/GXLegacy.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx.h"
#include "track/intersect_api.h"
#include "main/rcp_dolphin_api.h"
#include "dolphin/mtx/vec.h"
#include "main/vecmath.h"

f32 gCameraNearPlane = 2.5f;
f32 gCameraFarPlane = 10000.0f;
f32 gCameraAspectRatio = 1.3333334f;
f32 gCameraEffectViewportFarZ = 1.0f;

f32 gCameraFarPlaneTransitionStart;
f32 gCameraFarPlaneTransitionTarget;
f32 gCameraFovY;
f32 gCameraOrthoTop;
f32 gCameraOrthoBottom;
f32 gCameraOrthoLeft;
f32 gCameraOrthoRight;
s32 gCameraProjectionMode;
u8 gCameraCurrentViewIndex;
u8 gCameraShakeEnabled;
u16 gCameraPerspectiveNorm;
s8 gObjTransformMatrixSlot;
s16 cameraViewportYOffset;
s16 gCameraViewportYOffset;
s16 gCameraFarPlaneTransitionFrames;
s16 gCameraFarPlaneTransitionFramesLeft;

typedef struct CameraMatrixStorage {
    CameraMatrix inverseYawTransforms[0x1E];
    union {
        CameraMatrix yawTransforms[0x22];
        struct {
            CameraMatrix objectYawTransforms[0x1F];
            CameraMatrix scratchTransform;
            CameraMatrix remainingYawTransforms[2];
        };
    };
    f32 worldMatrix[64];
    CameraMatrix defaultModelMatrix;
    Camera cameras[CAMERA_COUNT];
    CameraMatrix viewRotationMatrix;
    CameraMatrix inverseViewRotationMatrix;
    CameraMatrix viewMatrix;
    CameraMatrix inverseViewMatrix;
    CameraProjectionMatrix projectionMatrix;
} CameraMatrixStorage;

STATIC_ASSERT(offsetof(CameraMatrixStorage, yawTransforms) == 0x780);
STATIC_ASSERT(offsetof(CameraMatrixStorage, scratchTransform) == 0xF40);
STATIC_ASSERT(offsetof(CameraMatrixStorage, worldMatrix) == 0x1000);
STATIC_ASSERT(offsetof(CameraMatrixStorage, defaultModelMatrix) == 0x1100);
STATIC_ASSERT(offsetof(CameraMatrixStorage, cameras) == 0x1140);
STATIC_ASSERT(offsetof(CameraMatrixStorage, projectionMatrix) == 0x16C0);
STATIC_ASSERT(sizeof(CameraMatrixStorage) == 0x1700);

void Obj_RotateLocalOffsetByYaw(f32* local, f32* out, s8 yawIndex) {
    s32 matrixOffset;
    f32* matrix;

    if (yawIndex < 0) {
        out[0] = local[0];
        out[1] = local[1];
        out[2] = local[2];
    } else {
        matrixOffset = yawIndex * 16;
        matrix = (f32*)gObjYawTransformMatrices + matrixOffset;
        Matrix_TransformPoint(matrix, local[0], local[1], local[2], &out[0], &out[1], &out[2]);
    }
}

void Camera_UpdateForObject(Camera* camera) {
    GameObject* parent;
    s32 matrixOffset;
    f32* matrix;

    parent = camera->parentObject;
    if (parent == NULL) {
        camera->worldX = camera->x;
        camera->worldY = camera->y;
        camera->worldZ = camera->z;
        camera->worldYaw = camera->yaw;
        camera->worldPitch = camera->pitch;
        camera->worldRoll = camera->roll;
    } else {
        matrixOffset = parent->anim.transformMatrixIndex * 16;
        matrix = (f32*)gObjYawTransformMatrices + matrixOffset;
        Matrix_TransformPoint(matrix, camera->x, camera->y, camera->z, &camera->worldX, &camera->worldY,
                              &camera->worldZ);
        camera->worldYaw = camera->yaw - parent->anim.rotX;
        camera->worldPitch = camera->pitch;
        camera->worldRoll = camera->roll;
    }
}

s32 Angle_AddWrappedS16(s32 angle, s16* delta) {
    if ((angle += *delta) > 0x8000) {
        angle -= 0xFFFF;
    }
    if (angle >= -0x8000) {
        return angle;
    }
    return angle + 0xFFFF;
}

s32 Angle_SubWrappedS16(s32 angle, s16* delta) {
    if ((angle -= *delta) > 0x8000) {
        angle -= 0xFFFF;
    }
    if (angle >= -0x8000) {
        return angle;
    }
    return angle + 0xFFFF;
}

void Obj_TransformLocalVectorToWorld(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, GameObject* obj) {
    f32 vec[3];
    s32 matrixOffset;

    vec[0] = x;
    vec[1] = y;
    vec[2] = z;
    matrixOffset = obj->anim.transformMatrixIndex * 16;
    Matrix_TransformVector((f32*)gObjYawTransformMatrices + matrixOffset, vec, vec);
    *outX = vec[0];
    *outY = vec[1];
    *outZ = vec[2];
}

void Obj_TransformWorldVectorToLocal(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, GameObject* obj) {
    f32 vec[3];
    s32 matrixOffset;

    vec[0] = x;
    vec[1] = y;
    vec[2] = z;
    matrixOffset = obj->anim.transformMatrixIndex * 16;
    Matrix_TransformVector((f32*)gObjInverseYawTransformMatrices + matrixOffset, vec, vec);
    *outX = vec[0];
    *outY = vec[1];
    *outZ = vec[2];
}

void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, GameObject* obj) {
    s32 matrixOffset;

    if (obj != NULL) {
        matrixOffset = obj->anim.transformMatrixIndex * 16;
        Matrix_TransformPoint((f32*)gObjInverseYawTransformMatrices + matrixOffset, x, y, z, outX, outY, outZ);
    } else {
        *outX = x;
        *outY = y;
        *outZ = z;
    }
}

void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, GameObject* obj) {
    s32 matrixOffset;

    if (obj != NULL) {
        matrixOffset = obj->anim.transformMatrixIndex * 16;
        Matrix_TransformPoint((f32*)gObjYawTransformMatrices + matrixOffset, x, y, z, outX, outY, outZ);
    } else {
        *outX = x;
        *outY = y;
        *outZ = z;
    }
}

void Obj_GetWorldPosition(GameObject* obj, f32* outX, f32* outY, f32* outZ) {
    GameObject* parent;
    s32 matrixOffset;

    parent = obj->anim.parent;
    if (parent == NULL) {
        *outX = obj->anim.localPosX;
        *outY = obj->anim.localPosY;
        *outZ = obj->anim.localPosZ;
    } else {
        matrixOffset = parent->anim.transformMatrixIndex * 16;
        Matrix_TransformPoint((f32*)gObjYawTransformMatrices + matrixOffset, obj->anim.localPosX, obj->anim.localPosY,
                              obj->anim.localPosZ, outX, outY, outZ);
    }
}

static void Obj_BuildTransformMatricesForYaw(GameObject* obj, s32 yawIndex) {
    CameraMatrixStorage* storage;
    GameObject* ancestors[4];
    MatrixTransform inverseTransform;
    f32* inverseYawMatrix;
    s32 matrixOffset;
    f32* yawMatrix;
    s8 ancestorCount;
    f32 savedScale;
    s8 isAncestor;
    f32* yawMatrices;

    storage = (CameraMatrixStorage*)gObjInverseYawTransformMatrices;
    matrixOffset = yawIndex * 16;
    yawMatrices = (f32*)storage->yawTransforms;
    yawMatrix = yawMatrices + matrixOffset;
    inverseYawMatrix = (f32*)gObjInverseYawTransformMatrices + matrixOffset;
    isAncestor = 0;
    ancestorCount = 0;
    while (obj != NULL) {
        ancestors[ancestorCount] = obj;
        ancestorCount++;
        savedScale = obj->anim.rootMotionScale;
        if ((obj->objectFlags & 8) == 0) {
            obj->anim.rootMotionScale = 1.0f;
        }

        if (isAncestor == 0) {
            setMatrixFromObjectPos(yawMatrix, (MatrixTransform*)&obj->anim);
        } else {
            setMatrixFromObjectPos(storage->scratchTransform, (MatrixTransform*)&obj->anim);
            mtx44_multSafe(yawMatrix, storage->scratchTransform, yawMatrix);
        }

        obj->anim.rootMotionScale = savedScale;
        obj = obj->anim.parent;
        isAncestor = 1;
    }

    while (ancestorCount > 0) {
        ancestorCount--;
        obj = ancestors[ancestorCount];
        inverseTransform.x = -obj->anim.localPosX;
        inverseTransform.y = -obj->anim.localPosY;
        inverseTransform.z = -obj->anim.localPosZ;
        if ((obj->objectFlags & 8) == 0) {
            inverseTransform.scale = 1.0f;
        } else {
            inverseTransform.scale = 1.0f / obj->anim.rootMotionScale;
        }
        inverseTransform.rotX = -obj->anim.rotX;
        inverseTransform.rotY = -obj->anim.rotY;
        inverseTransform.rotZ = -obj->anim.rotZ;
        mtxRotateByVec3s(inverseYawMatrix, &inverseTransform);
    }
}

void Obj_BuildTransformMatrices(GameObject* obj) {
    Obj_BuildTransformMatricesForYaw(obj, obj->anim.transformMatrixIndex);
}

s32 Obj_BuildTransformMatrixSlot(GameObject* obj) {
    Obj_BuildTransformMatricesForYaw(obj, gObjTransformMatrixSlot);
    gObjTransformMatrixSlot++;
    return gObjTransformMatrixSlot - 1;
}

static inline f32 Camera_Expf(f32 x, u32 iterations) {
    f32 y;
    f32 xp;
    f32 n;
    f32 yp;

    y = 1.0f;
    n = 1.0f;
    xp = x;
    yp = 1.0f;

    for (; iterations != 0; iterations--) {
        y += xp / yp;
        n += 1.0f;
        xp *= x;
        yp *= n;
    }

    return y;
}

void Camera_UpdateShakeAndFarPlane(void) {
    Camera* camera;
    f32 expTerm;
    f32 shakeTime;
    f32 sinePhase;
    f32 phaseScale;

    gCameraViewportYOffset = cameraViewportYOffset;
    if (gCameraFarPlaneTransitionFramesLeft != 0) {
        gCameraFarPlaneTransitionFramesLeft -= framesThisStep;
        if (gCameraFarPlaneTransitionFramesLeft < 0) {
            gCameraFarPlaneTransitionFramesLeft = 0;
        }
        gCameraFarPlane = ((f32)gCameraFarPlaneTransitionFramesLeft / gCameraFarPlaneTransitionFrames) *
                              (gCameraFarPlaneTransitionStart - gCameraFarPlaneTransitionTarget) +
                          gCameraFarPlaneTransitionTarget;
    }

    gObjTransformMatrixSlot = 0;
    camera = &gCameras[gCameraCurrentViewIndex];

    if (camera->shakeMode == 0) {
        camera->shakeCooldown--;
        while (camera->shakeCooldown < 0) {
            camera->shakeCooldown++;
            camera->shakeOffsetY = 0.9f * -camera->shakeOffsetY;
        }
    } else if (camera->shakeMode == 1) {
        expTerm = Camera_Expf(-camera->shakeDamping * (shakeTime = camera->shakeTime), 20);

        phaseScale = 65535.0f * camera->shakeFrequency;
        sinePhase = (3.1415927f * (phaseScale * shakeTime)) / 32768.0f;
        camera->shakeOffsetY = camera->shakeAmplitude * expTerm * mathCosf(sinePhase);
        if ((camera->shakeOffsetY < 0.1f) &&
            (camera->shakeOffsetY > -0.1f)) {
            camera->shakeOffsetY = 0.0f;
            camera->shakeMode = -1;
        }
        camera->shakeTime += timeDelta / 60.0f;
    }
}

u8 CameraShake_IsActive(void) {
    Camera* camera = &gCameras[gCameraCurrentViewIndex];

    return camera->shakeMode == 1;
}

void CameraShake_StartDampened(f32 amplitude, f32 frequency, f32 damping) {
    Camera* camera = &gCameras[0];

    camera->shakeOffsetY = amplitude;
    camera->shakeAmplitude = amplitude;
    camera->shakeFrequency = frequency;
    camera->shakeTime = 0.0f;
    camera->shakeDamping = damping;
    camera->shakeMode = 1;
}

void CameraShake_SetOffset(f32 offsetY) {
    Camera* cameraGroup = gCameras;
    int group;
    int i;

    for (group = 0; group < 2; group++) {
        for (i = 0; i < 6; i++) {
            Camera* camera = &cameraGroup[i];
            camera->shakeOffsetY = offsetY;
            camera->shakeMode = 0;
        }
        cameraGroup += 6;
    }
}

void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 intensity) {
    Camera* camera;
    s32 i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    s8 bounceMode;

    camera = gCameras;
    bounceMode = 0;
    for (i = 0; i <= 7; i++) {
        dx = x - camera[i].x;
        dy = y - camera[i].y;
        dz = z - camera[i].z;
        distance = sqrtf(dx * dx + dy * dy + dz * dz);
        if (distance < radius) {
            camera[i].shakeOffsetY = (intensity * (radius - distance)) / radius;
            camera[i].shakeMode = bounceMode;
        }
    }
}

f32* Camera_GetWorldMatrix(void) {
    return gCameraWorldMatrix;
}

void Camera_LoadModelViewMatrix(int unusedDisplayList, int unusedMatrixList, MatrixTransform* transform, f32 yScale,
                                f32 unusedOffsetY, f32* outMatrix) {
    f32* modelMatrix;

    if (outMatrix != NULL) {
        modelMatrix = outMatrix;
    } else {
        modelMatrix = gCameraDefaultModelMatrix;
    }

    transform->x -= playerMapOffsetX;
    transform->z -= playerMapOffsetZ;
    setMatrixFromObjectPos(modelMatrix, transform);
    if (yScale != 1.0f) {
        mtx44ScaleRow1(modelMatrix, yScale);
    }

    if (outMatrix == NULL) {
        mtx44Transpose(modelMatrix, (f32*)gCameraModelViewMatrix);
    } else {
        mtx44Transpose(outMatrix, (f32*)gCameraModelViewMatrix);
    }

    PSMTXConcat((MtxPtr)gCameraViewMatrix, (MtxPtr)gCameraModelViewMatrix, (MtxPtr)gCameraModelViewMatrix);
    GXLoadPosMtxImm(gCameraModelViewMatrix, GX_PNMTX0);
    transform->x += playerMapOffsetX;
    transform->z += playerMapOffsetZ;
}

/*
 * The fullscreen post-scene path deliberately selects index 4 even though the viewport table has four entries.
 * Retail reads the flags field at that out-of-bounds index, which lands 0x30 bytes into the adjacent viewport-transform
 * table.
 */
void Camera_SetupFullscreenViewport(void* viewportArg) {
    u32 resolution;
    u32 height;
    s32* viewportFlags;
    u32 width;
    u8 viewIndex;
    u32 halfWidth;
    s16 halfHeightQuarterPixels;

    gCameraCurrentViewIndex = 4;
    /* getScreenResolution packs height in the upper 16 bits and width in the lower 16 bits. */
    resolution = getScreenResolution();
    height = resolution >> 16;
    width = resolution & 0xFFFF;
    viewportFlags = &gCameraViewports[0].flags;

    if ((viewportFlags[gCameraCurrentViewIndex * (sizeof(CameraViewport) / sizeof(*viewportFlags))] & 1) == 0) {
        gxSetScissorRect(0, 0, 0, 0, width - 1, height - 1);
        halfWidth = width / 2;
        viewIndex = gCameraCurrentViewIndex;
        if ((viewportFlags[viewIndex * (sizeof(CameraViewport) / sizeof(*viewportFlags))] & 1) == 0) {
            gCameraViewportTransforms[viewIndex].translateX = (s16)(halfWidth * 4);
            halfHeightQuarterPixels = (s16)((height / 2) * 4);
            gCameraViewportTransforms[viewIndex].translateY = halfHeightQuarterPixels;
            gCameraViewportTransforms[viewIndex].scaleX = (s16)(halfWidth * 4);
            gCameraViewportTransforms[viewIndex].scaleY = halfHeightQuarterPixels;
        }
    } else {
        Camera_ApplyCurrentViewport(viewportArg);
        viewIndex = gCameraCurrentViewIndex;
        if ((viewportFlags[viewIndex * (sizeof(CameraViewport) / sizeof(*viewportFlags))] & 1) == 0) {
            gCameraViewportTransforms[viewIndex].translateX = 0;
            gCameraViewportTransforms[viewIndex].translateY = 0;
            gCameraViewportTransforms[viewIndex].scaleX = 0;
            gCameraViewportTransforms[viewIndex].scaleY = 0;
        }
    }

    gCameraCurrentViewIndex = 0;
}

void Camera_ClipToScreen(f32 clipX, f32 clipY, f32 clipZ, s32* outX, s32* outY, s32* outZ) {
    f32 coord;

    if (outX != NULL) {
        coord = clipX * (f32)(gCameraViewportTransforms[0].scaleX >> 2);
        coord = coord + (f32)(gCameraViewportTransforms[0].translateX >> 2);
        *outX = coord;
    }

    if (outY != NULL) {
        coord = clipY * (f32)(gCameraViewportTransforms[0].scaleY >> 2);
        coord = coord + (f32)(gCameraViewportTransforms[0].translateY >> 2);
        *outY = coord;
        *outY = 480 - *outY;
    }

    if (outZ != NULL) {
        *outZ = (s32)(16777215.0f * (1.0f + clipZ));
    }
}

void Camera_ProjectWorldSphere(f32 x, f32 y, f32 z, f32 radius, f32* outX, f32* outY, f32* outZ, f32* outRadiusX,
                               f32* outRadiusY, f32* outRadiusZ) {
    Vec pos;
    f32 clipW;
    f32 inverseW;

    pos.x = x;
    pos.y = y;
    pos.z = z;
    PSMTXMultVec((MtxPtr)gCameraViewMatrix, &pos, &pos);

    *outX =
        gCameraProjectionMatrix[0][3] + (gCameraProjectionMatrix[0][0] * pos.x + gCameraProjectionMatrix[0][1] * pos.y +
                                         gCameraProjectionMatrix[0][2] * pos.z);
    *outY =
        gCameraProjectionMatrix[1][3] + (gCameraProjectionMatrix[1][0] * pos.x + gCameraProjectionMatrix[1][1] * pos.y +
                                         gCameraProjectionMatrix[1][2] * pos.z);
    *outZ =
        gCameraProjectionMatrix[2][3] + (gCameraProjectionMatrix[2][0] * pos.x + gCameraProjectionMatrix[2][1] * pos.y +
                                         gCameraProjectionMatrix[2][2] * pos.z);

    clipW =
        gCameraProjectionMatrix[3][3] + (gCameraProjectionMatrix[3][0] * pos.x + gCameraProjectionMatrix[3][1] * pos.y +
                                         gCameraProjectionMatrix[3][2] * pos.z);
    if (clipW != 0.0f) {
        inverseW = 1.0f / clipW;
        *outX *= inverseW;
        *outY *= inverseW;
        *outZ *= inverseW;

        pos.z += radius;
        if (pos.z > -1.0f) {
            pos.z = -1.0f;
        }

        clipW = gCameraProjectionMatrix[3][3] +
                (gCameraProjectionMatrix[3][0] * pos.x + gCameraProjectionMatrix[3][1] * pos.y +
                 gCameraProjectionMatrix[3][2] * pos.z);
        if (clipW != 0.0f) {
            inverseW = 1.0f / clipW;
            *outRadiusX = fabsf(inverseW * (radius * gCameraProjectionMatrix[0][0]));
            *outRadiusY = fabsf(inverseW * (radius * gCameraProjectionMatrix[1][1]));
            *outRadiusZ = fabsf(inverseW * (radius * gCameraProjectionMatrix[2][2]));
        }
    }
}

void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 offset, f32* outX, f32* outY, f32* outZ) {
    Vec pos;
    Vec offsetVec;
    f32 clipW;
    f32 inverseW;

    pos.x = x;
    pos.y = y;
    pos.z = z;
    PSMTXMultVec((MtxPtr)gCameraViewMatrix, &pos, &pos);
    PSVECNormalize(&pos, &offsetVec);
    PSVECScale(&offsetVec, &offsetVec, offset);
    PSVECSubtract(&pos, &offsetVec, &pos);

    *outX =
        gCameraProjectionMatrix[0][3] + (gCameraProjectionMatrix[0][0] * pos.x + gCameraProjectionMatrix[0][1] * pos.y +
                                         gCameraProjectionMatrix[0][2] * pos.z);
    *outY =
        gCameraProjectionMatrix[1][3] + (gCameraProjectionMatrix[1][0] * pos.x + gCameraProjectionMatrix[1][1] * pos.y +
                                         gCameraProjectionMatrix[1][2] * pos.z);
    *outZ =
        gCameraProjectionMatrix[2][3] + (gCameraProjectionMatrix[2][0] * pos.x + gCameraProjectionMatrix[2][1] * pos.y +
                                         gCameraProjectionMatrix[2][2] * pos.z);

    clipW =
        gCameraProjectionMatrix[3][3] + (gCameraProjectionMatrix[3][0] * pos.x + gCameraProjectionMatrix[3][1] * pos.y +
                                         gCameraProjectionMatrix[3][2] * pos.z);
    if (clipW != 0.0f) {
        inverseW = 1.0f / clipW;
        *outX *= inverseW;
        *outY *= inverseW;
        *outZ *= inverseW;
    }
}

void Camera_ProjectWorldPoint(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, f32* outViewZ) {
    Vec pos;
    f32 clipW;
    f32 inverseW;

    pos.x = x;
    pos.y = y;
    pos.z = z;
    PSMTXMultVec((MtxPtr)gCameraViewMatrix, &pos, &pos);

    *outViewZ = pos.z;
    *outX =
        gCameraProjectionMatrix[0][3] + (gCameraProjectionMatrix[0][0] * pos.x + gCameraProjectionMatrix[0][1] * pos.y +
                                         gCameraProjectionMatrix[0][2] * pos.z);
    *outY =
        gCameraProjectionMatrix[1][3] + (gCameraProjectionMatrix[1][0] * pos.x + gCameraProjectionMatrix[1][1] * pos.y +
                                         gCameraProjectionMatrix[1][2] * pos.z);
    *outZ =
        gCameraProjectionMatrix[2][3] + (gCameraProjectionMatrix[2][0] * pos.x + gCameraProjectionMatrix[2][1] * pos.y +
                                         gCameraProjectionMatrix[2][2] * pos.z);

    clipW =
        gCameraProjectionMatrix[3][3] + (gCameraProjectionMatrix[3][0] * pos.x + gCameraProjectionMatrix[3][1] * pos.y +
                                         gCameraProjectionMatrix[3][2] * pos.z);
    if (clipW != 0.0f) {
        inverseW = 1.0f / clipW;
        *outX *= inverseW;
        *outY *= inverseW;
        *outZ *= inverseW;
    }
}

void Camera_ApplyCurrentViewport(void* viewportArg) {
    u16 width;
    int viewportY;
    u32 screenSize;

    screenSize = getScreenResolution();
    viewportY = screenSize >> 16;
    width = screenSize;
    screenSize = viewportY;
    viewportY = gCameraViewportYOffset + 6;
    screenSize -= viewportY;
    gxSetScissorRect(0, 0, 0, viewportY, width, screenSize);
}

void Camera_UpdateProjection(void* viewportArg, int unused) {
    u8 viewIndex = gCameraCurrentViewIndex;
    u8 activeViewIndex;
    u32 resolution = getScreenResolution();
    u32 screenWidth;
    u32 screenHeight;
    CameraViewport* viewports;
    CameraViewport* activeViewport;

    screenHeight = resolution >> 16;
    screenWidth = resolution & 0xFFFF;
    viewports = gCameraViewports;

    if ((viewports[viewIndex].flags & 1) != 0) {
        u8 savedViewIndex = gCameraCurrentViewIndex;

        gCameraCurrentViewIndex = viewIndex;
        gxSetScissorRect(0, 0, viewports[viewIndex & 0xFF].scissorX1, viewports[viewIndex & 0xFF].scissorY1,
                         viewports[viewIndex & 0xFF].scissorX2, viewports[viewIndex & 0xFF].scissorY2);

        activeViewport = gCameraViewports;
        activeViewIndex = gCameraCurrentViewIndex;
        activeViewport += activeViewIndex;
        if ((activeViewport->flags & 1) == 0) {
            gCameraViewportTransforms[activeViewIndex].translateX = 0;
            gCameraViewportTransforms[activeViewIndex].translateY = 0;
            gCameraViewportTransforms[activeViewIndex].scaleX = 0;
            gCameraViewportTransforms[activeViewIndex].scaleY = 0;
        }

        gCameraCurrentViewIndex = savedViewIndex;
        if (gCameraProjectionMode == 1) {
            C_MTXOrtho(gCameraProjectionMatrix, gCameraOrthoTop, gCameraOrthoBottom, gCameraOrthoLeft,
                       gCameraOrthoRight, gCameraNearPlane, gCameraFarPlane);
        } else {
            C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio, gCameraNearPlane,
                             gCameraFarPlane);
            C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveScaledMatrix, gCameraFovY, gCameraAspectRatio, 0.4f,
                                  0.4f, 0.5f, 0.5f);
            C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveMatrix, gCameraFovY, gCameraAspectRatio, 0.5f, 0.5f,
                                  0.5f, 0.5f);
            C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveFlipYMatrix, gCameraFovY, gCameraAspectRatio, 0.5f,
                                  -0.5f, 0.5f, 0.5f);
        }
        GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
        gCameraCurrentViewIndex = viewIndex;
    } else {
        u32 halfScreenWidth = screenWidth / 2;
        u32 halfScreenHeight = screenHeight / 2;

        activeViewIndex = gCameraCurrentViewIndex;
        activeViewport = gCameraViewports;
        activeViewport += activeViewIndex;
        if ((activeViewport->flags & 1) == 0) {
            gCameraViewportTransforms[activeViewIndex].translateX = (s16)(halfScreenWidth * 4);
            gCameraViewportTransforms[activeViewIndex].translateY = (s16)(halfScreenHeight * 4);
            gCameraViewportTransforms[activeViewIndex].scaleX = (s16)(halfScreenWidth * 4);
            gCameraViewportTransforms[activeViewIndex].scaleY = (s16)(halfScreenHeight * 4);
        }

        if (gCameraProjectionMode == 1) {
            C_MTXOrtho(gCameraProjectionMatrix, gCameraOrthoTop, gCameraOrthoBottom, gCameraOrthoLeft,
                       gCameraOrthoRight, gCameraNearPlane, gCameraFarPlane);
        } else {
            C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio, gCameraNearPlane,
                             gCameraFarPlane);
            C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveScaledMatrix, gCameraFovY, gCameraAspectRatio, 0.4f,
                                  0.4f, 0.5f, 0.5f);
            C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveMatrix, gCameraFovY, gCameraAspectRatio, 0.5f, 0.5f,
                                  0.5f, 0.5f);
            C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveFlipYMatrix, gCameraFovY, gCameraAspectRatio, 0.5f,
                                  -0.5f, 0.5f, 0.5f);
        }
        GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
        Camera_ApplyCurrentViewport(viewportArg);
        gCameraCurrentViewIndex = viewIndex;
    }
}

void Camera_GetFullViewportRect(s32* outLeft, s32* outTop, u32* outRight, s32* outBottom) {
    u32 resolution = getScreenResolution();

    *outLeft = 0;
    *outRight = resolution & 0xFFFF;
    *outTop = gCameraViewportYOffset + 6;
    *outBottom = (resolution >> 16) - (gCameraViewportYOffset + 6);
}

void Camera_SetCurrentViewIndex(int index) {
    if (index >= 0 && index < 4) {
        gCameraCurrentViewIndex = index;
        return;
    }
    gCameraCurrentViewIndex = 0;
}

f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z) {
    Camera* camera = &gCameras[gCameraCurrentViewIndex];
    f32 delta;
    f32 dz;
    f32 dx;
    f32 dy;

    delta = z - camera->z;
    dz = delta * delta;
    delta = x - camera->x;
    dx = delta * delta;
    delta = y - camera->y;
    dy = delta * delta;
    return sqrtf(dz + (dx + dy));
}

void Camera_SetCurrentViewRotation(int yaw, int pitch, int roll) {
    Camera* camera = &gCameras[gCameraCurrentViewIndex];

    camera->yaw = yaw;
    camera->pitch = pitch;
    camera->roll = roll;
}

void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z) {
    Camera* camera = &gCameras[gCameraCurrentViewIndex];

    camera->x = x;
    camera->y = y;
    camera->z = z;
}

f32* Camera_GetViewRotationMatrix(void) {
    return gCameraViewRotationMatrix;
}

f32* Camera_GetInverseViewRotationMatrix(void) {
    return gCameraInverseViewRotationMatrix;
}

f32* Camera_GetViewMatrix(void) {
    return gCameraViewMatrix;
}

f32* Camera_GetInverseViewMatrix(void) {
    return gCameraInverseViewMatrix;
}

void Camera_UpdateViewMatrices(void) {
    CameraMatrixStorage* storage;
    Camera* cameras;
    Camera* camera;
    MatrixTransform transform;
    f32 rotationMatrix[16];
    f32 shakeOffset = 0.0f;

    storage = (CameraMatrixStorage*)gObjInverseYawTransformMatrices;
    cameras = storage->cameras;
    camera = &cameras[gCameraCurrentViewIndex];
    transform.x = -(camera->x - playerMapOffsetX);
    transform.y = -camera->y;
    transform.z = -(camera->z - playerMapOffsetZ);
    transform.rotX = camera->yaw + 0x8000;
    transform.rotY = camera->pitch;
    transform.rotZ = camera->roll;
    transform.scale = 1.0f;
    if (pauseMenuGetState() == 0) {
        if (gCameraShakeEnabled != 0) {
            transform.y -= camera->shakeOffsetY;
        }
        transform.x += shakeOffset;
        transform.y += shakeOffset;
        transform.z += shakeOffset;
    }

    mtxRotateByVec3s(rotationMatrix, &transform);
    mtx44Transpose(rotationMatrix, storage->viewMatrix);

    transform.x = camera->x - playerMapOffsetX;
    transform.y = camera->y;
    transform.z = camera->z - playerMapOffsetZ;
    transform.rotX = -(camera->yaw + 0x8000);
    transform.rotY = -camera->pitch;
    transform.rotZ = -camera->roll;
    transform.scale = 1.0f;
    if (pauseMenuGetState() == 0) {
        if (gCameraShakeEnabled != 0) {
            transform.y += camera->shakeOffsetY;
        }
        transform.x -= shakeOffset;
        transform.y -= shakeOffset;
        transform.z -= shakeOffset;
    }

    setMatrixFromObjectPos(storage->worldMatrix, &transform);
    mtx44Transpose(storage->worldMatrix, storage->inverseViewMatrix);
    PSMTXCopy((MtxPtr)storage->viewMatrix, (MtxPtr)storage->viewRotationMatrix);
    storage->viewRotationMatrix[11] = storage->viewRotationMatrix[7] = storage->viewRotationMatrix[3] = 0.0f;
    PSMTXCopy((MtxPtr)storage->inverseViewMatrix, (MtxPtr)storage->inverseViewRotationMatrix);
    storage->inverseViewRotationMatrix[11] = storage->inverseViewRotationMatrix[7] =
        storage->inverseViewRotationMatrix[3] = 0.0f;
}

void Camera_ApplyFullViewport(void) {
    GXRenderModeObj* renderMode = gRenderModeObj;

    if (renderMode->field_rendering != 0) {
        GXSetViewportJitter(0.0f, 0.0f, renderMode->fbWidth, renderMode->xfbHeight, 0.0f,
                            1.0f, gViewportJitterField);
    } else {
        GXSetViewport(0.0f, 0.0f, renderMode->fbWidth, renderMode->xfbHeight, 0.0f,
                      1.0f);
    }
}

void Camera_ApplyEffectDepthViewport(void) {
    GXRenderModeObj* renderMode = gRenderModeObj;

    if (renderMode->field_rendering != 0) {
        GXSetViewportJitter(0.0f, 0.0f, renderMode->fbWidth, renderMode->xfbHeight, (-0.075f),
                            1.0f, gViewportJitterField);
    } else {
        GXSetViewport(0.0f, 0.0f, renderMode->fbWidth, renderMode->xfbHeight, (-0.075f),
                      gCameraEffectViewportFarZ);
    }
}

void Camera_ApplyTransparentViewport(void) {
    GXRenderModeObj* renderMode = gRenderModeObj;

    if (renderMode->field_rendering != 0) {
        GXSetViewportJitter(0.0f, 0.0f, renderMode->fbWidth, renderMode->xfbHeight, (-0.01f),
                            1.0f, gViewportJitterField);
    } else {
        GXSetViewport(0.0f, 0.0f, renderMode->fbWidth, renderMode->xfbHeight, (-0.01f), 1.0f);
    }
}

void Camera_ApplyDecalViewport(void) {
    GXRenderModeObj* renderMode = gRenderModeObj;

    if (renderMode->field_rendering != 0) {
        GXSetViewportJitter(0.0f, 0.0f, renderMode->fbWidth, renderMode->xfbHeight, (-0.05f),
                            1.0f, gViewportJitterField);
    } else {
        GXSetViewport(0.0f, 0.0f, renderMode->fbWidth, renderMode->xfbHeight, (-0.05f), 1.0f);
    }
}

u16 Camera_GetCurrentViewPitch(void) {
    return gCameras[gCameraCurrentViewIndex].pitch;
}

u16 Camera_GetCurrentViewYaw(void) {
    return gCameras[gCameraCurrentViewIndex].yaw;
}

Camera* Camera_GetCurrent(void) {
    return &gCameras[gCameraCurrentViewIndex];
}

int CameraShake_IsEnabled(void) {
    return gCameraShakeEnabled;
}

void CameraShake_Disable(void) {
    gCameraShakeEnabled = 0;
}

void CameraShake_Enable(void) {
    gCameraShakeEnabled = 1;
}

s16 Camera_GetViewportYOffset(void) {
    return cameraViewportYOffset;
}

void Camera_SetViewportYOffset(s16 yOffset) {
    cameraViewportYOffset = yOffset;
}

f32* Camera_GetProjectionMatrix(void) {
    return (f32*)gCameraProjectionMatrix;
}

void Camera_RebuildProjectionMatrix(void) {
    if (gCameraProjectionMode == 1) {
        C_MTXOrtho(gCameraProjectionMatrix, gCameraOrthoTop, gCameraOrthoBottom, gCameraOrthoLeft, gCameraOrthoRight,
                   gCameraNearPlane, gCameraFarPlane);
    } else {
        C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio, gCameraNearPlane, gCameraFarPlane);
        C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveScaledMatrix, gCameraFovY, gCameraAspectRatio, 0.4f, 0.4f,
                              0.5f, 0.5f);
        C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveMatrix, gCameraFovY, gCameraAspectRatio, 0.5f, 0.5f, 0.5f,
                              0.5f);
        C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveFlipYMatrix, gCameraFovY, gCameraAspectRatio, 0.5f, -0.5f,
                              0.5f, 0.5f);
    }
    GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
}

f32 Camera_GetFarPlane(void) {
    return gCameraFarPlane;
}

void Camera_SetFarPlane(f32 farPlane, int transitionFrames) {
    if (transitionFrames != 0) {
        s16 frames = transitionFrames;
        gCameraFarPlaneTransitionFrames = frames;
        gCameraFarPlaneTransitionFramesLeft = frames;
        gCameraFarPlaneTransitionStart = gCameraFarPlane;
        gCameraFarPlaneTransitionTarget = farPlane;
    } else {
        gCameraFarPlane = farPlane;
    }
}

f32 Camera_GetNearPlane(void) {
    return gCameraNearPlane;
}

f32 Camera_GetAspectRatio(void) {
    return gCameraAspectRatio;
}

void Camera_SetAspectRatio(f32 aspectRatio) {
    gCameraAspectRatio = aspectRatio;
}

f32 Camera_GetFovY(void) {
    return gCameraFovY;
}

void Camera_SetFovY(f32 fovY) {
    if (fovY == 0.0f) {
        fovY = 60.0f;
    }
    gCameraFovY = fovY;
}

const f32 gCameraDefaultFarPlane[] = {10000.0f};
const f32 gCameraDefaultPosition[] = {200.0f};

void Camera_InitState(void) {
    CameraMatrixStorage* storage = (CameraMatrixStorage*)gObjInverseYawTransformMatrices;
    u32 i;
    Camera* camera;

    for (i = 0; i < CAMERA_COUNT; i++) {
        camera = (Camera*)((u8*)storage + (u8)i * sizeof(Camera));
        camera = (Camera*)((u8*)camera + offsetof(CameraMatrixStorage, cameras));
        camera->roll = 0;
        camera->pitch = 0;
        camera->yaw = 0x7FF8;
        camera->x = gCameraDefaultPosition[0];
        camera->y = gCameraDefaultPosition[0];
        camera->z = gCameraDefaultPosition[0];
        camera->velocity.x = 0.0f;
        camera->velocity.y = 0.0f;
        camera->velocity.z = 0.0f;
        camera->shakeOffsetY = 0.0f;
        camera->parentObject = NULL;
        camera->shakePitchOffset = 0;
        camera->fovY = 60.0f;
    }

    gCameraCurrentViewIndex = 0;
    gCameraShakeEnabled = 0;
    gObjTransformMatrixSlot = 0;
    gCameraViewportYOffset = 0;
    cameraViewportYOffset = 0;
    gCameraFarPlane = gCameraDefaultFarPlane[0];
    gCameraFarPlaneTransitionFramesLeft = 0;
    gCameraFovY = 60.0f;
    gCameraProjectionMode = 0;

    if (gCameraProjectionMode == 1) {
        C_MTXOrtho(storage->projectionMatrix, gCameraOrthoTop, gCameraOrthoBottom, gCameraOrthoLeft, gCameraOrthoRight,
                   gCameraNearPlane, gCameraFarPlane);
    } else {
        C_MTXPerspective(storage->projectionMatrix, gCameraFovY, gCameraAspectRatio, gCameraNearPlane, gCameraFarPlane);
        C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveScaledMatrix, gCameraFovY, gCameraAspectRatio, 0.4f, 0.4f,
                              0.5f, 0.5f);
        C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveMatrix, gCameraFovY, gCameraAspectRatio, 0.5f, 0.5f, 0.5f,
                              0.5f);
        C_MTXLightPerspective((MtxPtr)gCameraLightPerspectiveFlipYMatrix, gCameraFovY, gCameraAspectRatio, 0.5f,
                              (-0.5f), 0.5f, 0.5f);
    }
    GXSetProjection(storage->projectionMatrix, gCameraProjectionMode);

    mtx44Perspective(storage->worldMatrix + 32, &gCameraPerspectiveNorm, gCameraFovY, gCameraAspectRatio,
                     gCameraNearPlane, gCameraFarPlane, 1.0f);
    copyMatrix44(storage->worldMatrix + 32, storage->yawTransforms[33]);
}

CameraProjectionMatrix gCameraProjectionMatrix;
CameraMatrix gCameraInverseViewMatrix;
CameraMatrix gCameraViewMatrix;
CameraMatrix gCameraInverseViewRotationMatrix;
CameraMatrix gCameraViewRotationMatrix;
Camera gCameras[CAMERA_COUNT];
CameraMatrix gCameraDefaultModelMatrix;
f32 gCameraWorldMatrix[64];
CameraMatrix gObjYawTransformMatrices[0x22];
CameraMatrix gObjInverseYawTransformMatrices[0x1E];

CameraViewport gCameraViewports[4] = {
    {0, 0, 320, 240, 160, 120, 320, 240, 0, 0, 319, 239, 0},
    {0, 0, 320, 240, 160, 120, 320, 240, 0, 0, 319, 239, 0},
    {0, 0, 320, 240, 160, 120, 320, 240, 0, 0, 319, 239, 0},
    {0, 0, 320, 240, 160, 120, 320, 240, 0, 0, 319, 239, 0},
};

CameraViewportTransform gCameraViewportTransforms[20] = {
    {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0},
    {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0},
    {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0},
    {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0},
    {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0},
    {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0},
    {0, 0, 511, 0, 0, 0, 511, 0}, {0, 0, 511, 0, 0, 0, 511, 0},
};
