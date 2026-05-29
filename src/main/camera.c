#include "ghidra_import.h"
#include "main/engine_shared.h"

#pragma scheduling off
#pragma peephole off
void Obj_RotateLocalOffsetByYaw(f32 *local, f32 *out, s8 yawIndex)
{
    s32 matrixIndex;
    f32 *matrix;

    if (yawIndex < 0) {
        out[0] = local[0];
        out[1] = local[1];
        out[2] = local[2];
    } else {
        matrixIndex = yawIndex << 4;
        matrix = (f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2));
        Matrix_TransformPoint(matrix, local[0], local[1], local[2], &out[0], &out[1], &out[2]);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Obj_UpdateWorldTransform(s16 *obj)
{
    s16 *parent;
    s32 matrixIndex;
    f32 *matrix;

    parent = *(s16 **)(obj + 0x20);
    if (parent == (s16 *)0) {
        *(f32 *)(obj + 0x22) = *(f32 *)(obj + 6);
        *(f32 *)(obj + 0x24) = *(f32 *)(obj + 8);
        *(f32 *)(obj + 0x26) = *(f32 *)(obj + 10);
        obj[0x28] = obj[0];
        obj[0x29] = obj[1];
        obj[0x2A] = obj[2];
    } else {
        matrixIndex = *(s8 *)((u8 *)parent + 0x35) << 4;
        matrix = (f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2));
        Matrix_TransformPoint(matrix, *(f32 *)(obj + 6), *(f32 *)(obj + 8), *(f32 *)(obj + 10),
                              (f32 *)(obj + 0x22), (f32 *)(obj + 0x24), (f32 *)(obj + 0x26));
        obj[0x28] = obj[0] - parent[0];
        obj[0x29] = obj[1];
        obj[0x2A] = obj[2];
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
s32 Angle_AddWrappedS16(s32 angle, s16 *delta)
{
    if ((angle += *delta) > 0x8000) {
        angle -= 0xFFFF;
    }
    if (angle >= -0x8000) {
        return angle;
    }
    return angle + 0xFFFF;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
s32 Angle_SubWrappedS16(s32 angle, s16 *delta)
{
    if ((angle -= *delta) > 0x8000) {
        angle -= 0xFFFF;
    }
    if (angle >= -0x8000) {
        return angle;
    }
    return angle + 0xFFFF;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Obj_TransformLocalVectorToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj)
{
    f32 vec[3];
    s32 matrixIndex;

    vec[0] = x;
    vec[1] = y;
    vec[2] = z;
    matrixIndex = *(s8 *)(obj + 0x35) << 4;
    Matrix_TransformVector((f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2)), vec, vec);
    *outX = vec[0];
    *outY = vec[1];
    *outZ = vec[2];
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Obj_TransformWorldVectorToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj)
{
    f32 vec[3];
    s32 matrixIndex;

    vec[0] = x;
    vec[1] = y;
    vec[2] = z;
    matrixIndex = *(s8 *)(obj + 0x35) << 4;
    Matrix_TransformVector((f32 *)((u8 *)gObjInverseYawTransformMatrices + (matrixIndex << 2)), vec, vec);
    *outX = vec[0];
    *outY = vec[1];
    *outZ = vec[2];
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj)
{
    s32 matrixIndex;

    if (obj != 0) {
        matrixIndex = *(s8 *)(obj + 0x35) << 4;
        Matrix_TransformPoint((f32 *)((u8 *)gObjInverseYawTransformMatrices + (matrixIndex << 2)), x, y, z, outX, outY,
                              outZ);
    } else {
        *outX = x;
        *outY = y;
        *outZ = z;
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj)
{
    s32 matrixIndex;

    if (obj != 0) {
        matrixIndex = *(s8 *)(obj + 0x35) << 4;
        Matrix_TransformPoint((f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2)), x, y, z, outX, outY, outZ);
    } else {
        *outX = x;
        *outY = y;
        *outZ = z;
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Obj_GetWorldPosition(u32 obj, f32 *outX, f32 *outY, f32 *outZ)
{
    u32 parent;
    s32 matrixIndex;

    parent = *(u32 *)(obj + 0x30);
    if (parent == 0) {
        *outX = *(f32 *)(obj + 0x0C);
        *outY = *(f32 *)(obj + 0x10);
        *outZ = *(f32 *)(obj + 0x14);
    } else {
        matrixIndex = *(s8 *)(parent + 0x35) << 4;
        Matrix_TransformPoint((f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2)), *(f32 *)(obj + 0x0C),
                              *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14), outX, outY, outZ);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Obj_BuildTransformMatricesForYaw(u32 obj, s32 yawIndex)
{
    u32 ancestors[4];
    ObjMatrixBuildTransform inverseTransform;
    u32 current;
    s32 matrixIndex;
    f32 *yawMatrix;
    f32 *inverseYawMatrix;
    f32 savedScale;
    s8 ancestorCount;
    s32 hasParent;

    current = obj;
    matrixIndex = yawIndex << 4;
    inverseYawMatrix = (f32 *)((u8 *)gObjInverseYawTransformMatrices + (matrixIndex << 2));
    yawMatrix = (f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2));
    hasParent = 0;
    ancestorCount = 0;
    while (current != 0) {
        ancestors[ancestorCount] = current;
        ancestorCount++;
        savedScale = *(f32 *)(current + 0x08);
        if ((*(u16 *)(current + 0xB0) & 8) == 0) {
            *(f32 *)(current + 0x08) = lbl_803DE5F0;
        }

        if (hasParent == 0) {
            setMatrixFromObjectPos(yawMatrix, (void *)current);
        } else {
            setMatrixFromObjectPos((f32 *)&DAT_80338c30, (void *)current);
            mtxFn_80022404(yawMatrix, (f32 *)&DAT_80338c30, yawMatrix);
        }

        *(f32 *)(current + 0x08) = savedScale;
        current = *(u32 *)(current + 0x30);
        hasParent = 1;
    }

    while (ancestorCount > 0) {
        ancestorCount--;
        current = ancestors[ancestorCount];
        inverseTransform.x = -*(f32 *)(current + 0x0C);
        inverseTransform.y = -*(f32 *)(current + 0x10);
        inverseTransform.z = -*(f32 *)(current + 0x14);
        if ((*(u16 *)(current + 0xB0) & 8) == 0) {
            inverseTransform.scale = lbl_803DE5F0;
        } else {
            inverseTransform.scale = lbl_803DE5F0 / *(f32 *)(current + 0x08);
        }
        inverseTransform.rotX = -*(s16 *)(current + 0x00);
        inverseTransform.rotY = -*(s16 *)(current + 0x02);
        inverseTransform.rotZ = -*(s16 *)(current + 0x04);
        mtxRotateByVec3s(inverseYawMatrix, &inverseTransform);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Obj_BuildTransformMatrices(u32 obj)
{
    Obj_BuildTransformMatricesForYaw(obj, *(s8 *)(obj + 0x35));
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
s32 Obj_BuildTransformMatrixSlot(u32 obj)
{
    Obj_BuildTransformMatricesForYaw(obj, gObjTransformMatrixSlot);
    gObjTransformMatrixSlot++;
    return gObjTransformMatrixSlot - 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32* Camera_GetViewRotationMatrix(void)
{
    return gCameraViewRotationMatrix;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32* Camera_GetInverseViewRotationMatrix(void)
{
    return gCameraInverseViewRotationMatrix;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32* Camera_GetViewMatrix(void)
{
    return gCameraViewMatrix;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32* Camera_GetInverseViewMatrix(void)
{
    return gCameraInverseViewMatrix;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void* Camera_GetCurrentViewSlot(void)
{
    return &gCameraShakeSlots[gCameraCurrentViewIndex];
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u8 CameraShake_IsActive(void)
{
    s32 offset = gCameraCurrentViewIndex * sizeof(CameraViewSlot);
    CameraViewSlot* slot = (CameraViewSlot*)((u8*)gCameraShakeSlots + offset);

    return slot->shakeActive == 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff)
{
    CameraViewSlot* slot = &gCameraShakeSlots[0];

    slot->shakeMagnitude = magnitude;
    slot->shakeMagnitudeTarget = magnitude;
    slot->shakeDuration = duration;
    slot->shakeTimer = lbl_803DE60C;
    slot->shakeFalloff = falloff;
    slot->shakeActive = 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void CameraShake_SetAllMagnitudes(f32 magnitude)
{
    CameraViewSlot* slot = gCameraShakeSlots;

    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;

    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 magnitude)
{
    CameraViewSlot* slot;
    s32 i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    s8 inactive;

    i = 0;
    slot = gCameraShakeSlots;
    inactive = 0;
    do {
        dx = x - slot->x;
        dy = y - slot->y;
        dz = z - slot->z;
        distance = sqrtf(dx * dx + dy * dy + dz * dz);
        if (distance < radius) {
            slot->shakeMagnitude = (magnitude * (radius - distance)) / radius;
            slot->shakeActive = inactive;
        }
        slot++;
        i++;
    } while (i <= 7);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void* fn_8000E814(void)
{
    return lbl_80338090;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_LoadModelViewMatrix(f32 scale, void* unused0, void* unused1, CameraViewSlot* transform, f32* matrix)
{
    f32* modelMatrix;

    if (matrix != NULL) {
        modelMatrix = matrix;
    } else {
        modelMatrix = lbl_80338190;
    }

    transform->x -= playerMapOffsetX;
    transform->z -= playerMapOffsetZ;
    setMatrixFromObjectPos(modelMatrix, transform);
    if (lbl_803DE5F0 != scale) {
        mtxFn_80021ec0(modelMatrix, scale);
    }

    if (matrix == NULL) {
        mtx44Transpose(modelMatrix, lbl_803967C0);
    } else {
        mtx44Transpose(matrix, lbl_803967C0);
    }

    PSMTXConcat(gCameraViewMatrix, lbl_803967C0, lbl_803967C0);
    GXLoadPosMtxImm(lbl_803967C0, 0);
    transform->x += playerMapOffsetX;
    transform->z += playerMapOffsetZ;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_NdcToScreen(f32 ndcX, f32 ndcY, f32 ndcZ, s32* outX, s32* outY, s32* outZ)
{
    if (outX != NULL) {
        *outX = (s32)(ndcX * (f32)(lbl_802C5ED0[0] >> 2) + (f32)(lbl_802C5ED0[4] >> 2));
    }

    if (outY != NULL) {
        *outY = (s32)(ndcY * (f32)(lbl_802C5ED0[1] >> 2) + (f32)(lbl_802C5ED0[5] >> 2));
        *outY = 0x1E0 - *outY;
    }

    if (outZ != NULL) {
        *outZ = (s32)(lbl_803DE620 * (lbl_803DE5F0 + ndcZ));
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void screenFn_8000e944(void* viewportArg)
{
    u32 resolution;
    u32 width;
    u32 height;
    u32* viewportFlags;
    u8 viewIndex;
    s16 halfWidth;
    s16 halfHeight;

    gCameraCurrentViewIndex = 4;
    resolution = getScreenResolution();
    width = resolution >> 16;
    height = resolution & 0xFFFF;
    viewportFlags = (u32*)(lbl_802C5E00 + 0x30);

    if ((*(u32*)((u8*)viewportFlags + gCameraCurrentViewIndex * 0x34) & 1) == 0) {
        gxSetScissorRect(0, 0, 0, 0, height - 1, width - 1);
        halfWidth = (s16)((height >> 1) << 2);
        viewIndex = gCameraCurrentViewIndex;
        if ((*(u32*)((u8*)viewportFlags + viewIndex * 0x34) & 1) == 0) {
            halfHeight = (s16)((width >> 1) << 2);
            lbl_802C5ED0[viewIndex * 8 + 4] = halfWidth;
            lbl_802C5ED0[viewIndex * 8 + 5] = halfHeight;
            lbl_802C5ED0[viewIndex * 8 + 0] = halfWidth;
            lbl_802C5ED0[viewIndex * 8 + 1] = halfHeight;
        }
    } else {
        Camera_ApplyCurrentViewport(viewportArg);
        viewIndex = gCameraCurrentViewIndex;
        if ((*(u32*)((u8*)viewportFlags + viewIndex * 0x34) & 1) == 0) {
            lbl_802C5ED0[viewIndex * 8 + 4] = 0;
            lbl_802C5ED0[viewIndex * 8 + 5] = 0;
            lbl_802C5ED0[viewIndex * 8 + 0] = 0;
            lbl_802C5ED0[viewIndex * 8 + 1] = 0;
        }
    }

    gCameraCurrentViewIndex = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_ProjectWorldPoint(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, f32* outViewZ)
{
    f32 pos[3];
    f32 w;
    f32 invW;

    pos[0] = x;
    pos[1] = y;
    pos[2] = z;
    PSMTXMultVec(gCameraViewMatrix, pos, pos);

    *outViewZ = pos[2];
    *outX = gCameraProjectionMatrix[3] +
            gCameraProjectionMatrix[2] * pos[2] +
            gCameraProjectionMatrix[0] * pos[0] +
            gCameraProjectionMatrix[1] * pos[1];
    *outY = gCameraProjectionMatrix[7] +
            gCameraProjectionMatrix[6] * pos[2] +
            gCameraProjectionMatrix[4] * pos[0] +
            gCameraProjectionMatrix[5] * pos[1];
    *outZ = gCameraProjectionMatrix[11] +
            gCameraProjectionMatrix[10] * pos[2] +
            gCameraProjectionMatrix[8] * pos[0] +
            gCameraProjectionMatrix[9] * pos[1];

    w = gCameraProjectionMatrix[15] +
        gCameraProjectionMatrix[14] * pos[2] +
        gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1];
    if (w != lbl_803DE60C) {
        invW = lbl_803DE5F0 / w;
        *outX *= invW;
        *outY *= invW;
        *outZ *= invW;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 offset, f32* outX, f32* outY, f32* outZ)
{
    f32 pos[3];
    f32 offsetVec[3];
    f32 w;
    f32 invW;

    pos[0] = x;
    pos[1] = y;
    pos[2] = z;
    PSMTXMultVec(gCameraViewMatrix, pos, pos);
    PSVECNormalize(pos, offsetVec);
    PSVECScale(offsetVec, offsetVec, offset);
    PSVECSubtract(pos, offsetVec, pos);

    *outX = gCameraProjectionMatrix[3] +
            gCameraProjectionMatrix[2] * pos[2] +
            gCameraProjectionMatrix[0] * pos[0] +
            gCameraProjectionMatrix[1] * pos[1];
    *outY = gCameraProjectionMatrix[7] +
            gCameraProjectionMatrix[6] * pos[2] +
            gCameraProjectionMatrix[4] * pos[0] +
            gCameraProjectionMatrix[5] * pos[1];
    *outZ = gCameraProjectionMatrix[11] +
            gCameraProjectionMatrix[10] * pos[2] +
            gCameraProjectionMatrix[8] * pos[0] +
            gCameraProjectionMatrix[9] * pos[1];

    w = gCameraProjectionMatrix[15] +
        gCameraProjectionMatrix[14] * pos[2] +
        gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1];
    if (w != lbl_803DE60C) {
        invW = lbl_803DE5F0 / w;
        *outX *= invW;
        *outY *= invW;
        *outZ *= invW;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_ProjectWorldSphere(
    f32 x,
    f32 y,
    f32 z,
    f32 radius,
    f32* outX,
    f32* outY,
    f32* outZ,
    f32* outRadiusX,
    f32* outRadiusY,
    f32* outRadiusZ)
{
    f32 pos[3];
    f32 w;
    f32 invW;

    pos[0] = x;
    pos[1] = y;
    pos[2] = z;
    PSMTXMultVec(gCameraViewMatrix, pos, pos);

    *outX = gCameraProjectionMatrix[3] +
            gCameraProjectionMatrix[2] * pos[2] +
            gCameraProjectionMatrix[0] * pos[0] +
            gCameraProjectionMatrix[1] * pos[1];
    *outY = gCameraProjectionMatrix[7] +
            gCameraProjectionMatrix[6] * pos[2] +
            gCameraProjectionMatrix[4] * pos[0] +
            gCameraProjectionMatrix[5] * pos[1];
    *outZ = gCameraProjectionMatrix[11] +
            gCameraProjectionMatrix[10] * pos[2] +
            gCameraProjectionMatrix[8] * pos[0] +
            gCameraProjectionMatrix[9] * pos[1];

    w = gCameraProjectionMatrix[15] +
        gCameraProjectionMatrix[14] * pos[2] +
        gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1];
    if (w != lbl_803DE60C) {
        invW = lbl_803DE5F0 / w;
        *outX *= invW;
        *outY *= invW;
        *outZ *= invW;

        pos[2] += radius;
        if (pos[2] > lbl_803DE624) {
            pos[2] = lbl_803DE624;
        }

        w = gCameraProjectionMatrix[15] +
            gCameraProjectionMatrix[14] * pos[2] +
            gCameraProjectionMatrix[12] * pos[0] +
            gCameraProjectionMatrix[13] * pos[1];
        if (w != lbl_803DE60C) {
            invW = lbl_803DE5F0 / w;
            *outRadiusX = fabsf(invW * (radius * gCameraProjectionMatrix[0]));
            *outRadiusY = fabsf(invW * (radius * gCameraProjectionMatrix[5]));
            *outRadiusZ = fabsf(invW * (radius * gCameraProjectionMatrix[10]));
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void viewportEffectFn_8000e380(void)
{
    CameraViewSlot* slot;
    f32 falloffTime;
    f32 shakeTimer;
    f32 expTerm;
    f32 n;
    f32 term;
    f32 factorial;
    f32 one;
    f32 sinePhase;
    s32 i;

    lbl_803DC884 = lbl_803DC886;
    if (lbl_803DC880 != 0) {
        lbl_803DC880 -= framesThisStep;
        if (lbl_803DC880 < 0) {
            lbl_803DC880 = 0;
        }
        gCameraFarPlane = ((f32)lbl_803DC880 / (f32)lbl_803DC882) * (lbl_803DC8AC - lbl_803DC8A8) + lbl_803DC8A8;
    }

    gObjTransformMatrixSlot = 0;
    slot = &gCameraShakeSlots[gCameraCurrentViewIndex];

    if (slot->shakeActive == 0) {
        slot->shakeFlipTimer--;
        while (slot->shakeFlipTimer < 0) {
            slot->shakeFlipTimer++;
            slot->shakeMagnitude = lbl_803DE5F4 * -slot->shakeMagnitude;
        }
    } else if (slot->shakeActive == 1) {
        falloffTime = -slot->shakeFalloff;
        shakeTimer = slot->shakeTimer;
        falloffTime *= shakeTimer;
        expTerm = lbl_803DE5F0;
        n = expTerm;
        term = falloffTime;
        factorial = expTerm;
        one = expTerm;

        for (i = 0; i < 2; i++) {
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
        }

        sinePhase = (lbl_803DE5F8 * (lbl_803DE5FC * slot->shakeDuration * shakeTimer)) / lbl_803DE600;
        slot->shakeMagnitude = slot->shakeMagnitudeTarget * expTerm * sin(sinePhase);
        if ((slot->shakeMagnitude < lbl_803DE604) && (slot->shakeMagnitude > lbl_803DE608)) {
            slot->shakeMagnitude = lbl_803DE60C;
            slot->shakeActive = -1;
        }
        slot->shakeTimer += timeDelta / lbl_803DE610;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Camera_ApplyCurrentViewport(void* viewportArg)
{
    u32 resolution = getScreenResolution();
    int width = resolution >> 16;
    int height = resolution & 0xffff;
    int viewportY = lbl_803DC884 + 6;

    gxSetScissorRect(0, 0, 0, viewportY, height, width - viewportY);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_UpdateProjection(void* viewportArg)
{
    u8 viewIndex = gCameraCurrentViewIndex;
    u8 activeViewIndex;
    u32 resolution = getScreenResolution();
    u32 screenWidth = resolution >> 16;
    u32 screenHeight = resolution & 0xffff;
    u8* viewportEntry = lbl_802C5E00 + viewIndex * 0x34;

    if ((*(u32*)(viewportEntry + 0x30) & 1) != 0) {
        u8 savedViewIndex = gCameraCurrentViewIndex;

        gCameraCurrentViewIndex = viewIndex;
        gxSetScissorRect(0, 0,
                         *(s32*)(viewportEntry + 0x20),
                         *(s32*)(viewportEntry + 0x24),
                         *(s32*)(viewportEntry + 0x28),
                         *(s32*)(viewportEntry + 0x2c));

        activeViewIndex = gCameraCurrentViewIndex;
        viewportEntry = lbl_802C5E00 + activeViewIndex * 0x34;
        if ((*(u32*)(viewportEntry + 0x30) & 1) == 0) {
            lbl_802C5ED0[activeViewIndex * 8 + 4] = 0;
            lbl_802C5ED0[activeViewIndex * 8 + 5] = 0;
            lbl_802C5ED0[activeViewIndex * 8 + 0] = 0;
            lbl_802C5ED0[activeViewIndex * 8 + 1] = 0;
        }

        gCameraCurrentViewIndex = savedViewIndex;
        if (gCameraProjectionMode == 1) {
            C_MTXOrtho(gCameraProjectionMatrix, lbl_803DC8A0, lbl_803DC89C, lbl_803DC898,
                       lbl_803DC894, gCameraNearPlane, gCameraFarPlane);
        } else {
            C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio,
                             gCameraNearPlane, gCameraFarPlane);
            C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                                  lbl_803DE628, lbl_803DE62C, lbl_803DE62C);
            C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE62C, lbl_803DE62C, lbl_803DE62C);
            C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE630, lbl_803DE62C, lbl_803DE62C);
        }
        GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
        gCameraCurrentViewIndex = viewIndex;
    } else {
        u32 halfScreenHeight = screenHeight >> 1;
        u32 halfScreenWidth = screenWidth >> 1;

        activeViewIndex = gCameraCurrentViewIndex;
        viewportEntry = lbl_802C5E00 + activeViewIndex * 0x34;
        if ((*(u32*)(viewportEntry + 0x30) & 1) == 0) {
            s16 scaledHalfHeight = (s16)(halfScreenHeight << 2);
            s16 scaledHalfWidth = (s16)(halfScreenWidth << 2);

            lbl_802C5ED0[activeViewIndex * 8 + 4] = scaledHalfHeight;
            lbl_802C5ED0[activeViewIndex * 8 + 5] = scaledHalfWidth;
            lbl_802C5ED0[activeViewIndex * 8 + 0] = scaledHalfHeight;
            lbl_802C5ED0[activeViewIndex * 8 + 1] = scaledHalfWidth;
        }

        if (gCameraProjectionMode == 1) {
            C_MTXOrtho(gCameraProjectionMatrix, lbl_803DC8A0, lbl_803DC89C, lbl_803DC898,
                       lbl_803DC894, gCameraNearPlane, gCameraFarPlane);
        } else {
            C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio,
                             gCameraNearPlane, gCameraFarPlane);
            C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                                  lbl_803DE628, lbl_803DE62C, lbl_803DE62C);
            C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE62C, lbl_803DE62C, lbl_803DE62C);
            C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE630, lbl_803DE62C, lbl_803DE62C);
        }
        GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
        Camera_ApplyCurrentViewport(viewportArg);
        gCameraCurrentViewIndex = viewIndex;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_GetCurrentViewport(s32* outX, s32* outY, u32* outHeight, s32* outWidth)
{
    u32 resolution = getScreenResolution();

    *outX = 0;
    *outHeight = resolution & 0xffff;
    *outY = lbl_803DC884 + 6;
    *outWidth = (resolution >> 16) - (lbl_803DC884 + 6);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_SetCurrentViewIndex(int index)
{
    if (index >= 0 && index < 4) {
        gCameraCurrentViewIndex = index;
        return;
    }
    gCameraCurrentViewIndex = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];
    f32 dz = z - slot->z;
    f32 dx = x - slot->x;
    f32 dy = y - slot->y;

    return sqrtf(dx * dx + dy * dy + dz * dz);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_SetCurrentViewRotation(int pitch, int yaw, int roll)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];

    slot->pitch = pitch;
    slot->yaw = yaw;
    slot->roll = roll;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];

    slot->x = x;
    slot->y = y;
    slot->z = z;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_UpdateViewMatrices(void)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];
    CameraMatrixTransform transform;
    f32 rotationMatrix[16];

    transform.x = -(slot->x - playerMapOffsetX);
    transform.y = -slot->y;
    transform.z = -(slot->z - playerMapOffsetZ);
    transform.pitch = slot->pitch - 0x8000;
    transform.yaw = slot->yaw;
    transform.roll = slot->roll;
    transform.scale = lbl_803DE5F0;
    if (pauseMenuGetState() == 0) {
        if (lbl_803DC88C != 0) {
            transform.y -= slot->shakeMagnitude;
        }
        transform.x += lbl_803DE60C;
        transform.y += lbl_803DE60C;
        transform.z += lbl_803DE60C;
    }

    mtxRotateByVec3s(rotationMatrix, &transform);
    mtx44Transpose(rotationMatrix, gCameraViewMatrix);

    transform.x = slot->x - playerMapOffsetX;
    transform.y = slot->y;
    transform.z = slot->z - playerMapOffsetZ;
    transform.pitch = -(slot->pitch - 0x8000);
    transform.yaw = -slot->yaw;
    transform.roll = -slot->roll;
    transform.scale = lbl_803DE5F0;
    if (pauseMenuGetState() == 0) {
        if (lbl_803DC88C != 0) {
            transform.y += slot->shakeMagnitude;
        }
        transform.x -= lbl_803DE60C;
        transform.y -= lbl_803DE60C;
        transform.z -= lbl_803DE60C;
    }

    setMatrixFromObjectPos((f32*)lbl_80338090, &transform);
    mtx44Transpose((f32*)lbl_80338090, gCameraInverseViewMatrix);
    PSMTXCopy(gCameraViewMatrix, gCameraViewRotationMatrix);
    gCameraViewRotationMatrix[3] = lbl_803DE60C;
    gCameraViewRotationMatrix[7] = lbl_803DE60C;
    gCameraViewRotationMatrix[11] = lbl_803DE60C;
    PSMTXCopy(gCameraInverseViewMatrix, gCameraInverseViewRotationMatrix);
    gCameraInverseViewRotationMatrix[3] = lbl_803DE60C;
    gCameraInverseViewRotationMatrix[7] = lbl_803DE60C;
    gCameraInverseViewRotationMatrix[11] = lbl_803DE60C;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_ApplyFullViewport(void)
{
    CameraRenderMode* renderMode = lbl_803DCCF0;

    if (renderMode->useViewportJitter != 0) {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                            (f32)renderMode->xfbHeight, lbl_803DE60C, lbl_803DE5F0,
                            lbl_803DCCBC);
    } else {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                      (f32)renderMode->xfbHeight, lbl_803DE60C, lbl_803DE5F0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8000F83C(void)
{
    CameraRenderMode* renderMode = lbl_803DCCF0;

    if (renderMode->useViewportJitter != 0) {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                            (f32)renderMode->xfbHeight, lbl_803DE640, lbl_803DE5F0,
                            lbl_803DCCBC);
    } else {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                      (f32)renderMode->xfbHeight, lbl_803DE640, lbl_803DB26C);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8000F8F8(void)
{
    CameraRenderMode* renderMode = lbl_803DCCF0;

    if (renderMode->useViewportJitter != 0) {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                            (f32)renderMode->xfbHeight, lbl_803DE644, lbl_803DE5F0,
                            lbl_803DCCBC);
    } else {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                      (f32)renderMode->xfbHeight, lbl_803DE644, lbl_803DE5F0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8000F9B4(void)
{
    CameraRenderMode* renderMode = lbl_803DCCF0;

    if (renderMode->useViewportJitter != 0) {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                            (f32)renderMode->xfbHeight, lbl_803DE648, lbl_803DE5F0,
                            lbl_803DCCBC);
    } else {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                      (f32)renderMode->xfbHeight, lbl_803DE648, lbl_803DE5F0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u16 fn_8000FA70(void)
{
    return (u16)gCameraShakeSlots[gCameraCurrentViewIndex].yaw;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u16 fn_8000FA90(void)
{
    return (u16)gCameraShakeSlots[gCameraCurrentViewIndex].pitch;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u8 Camera_IsViewYOffsetEnabled(void)
{
    return lbl_803DC88C;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_DisableViewYOffset(void)
{
    lbl_803DC88C = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_EnableViewYOffset(void)
{
    lbl_803DC88C = 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
s16 Camera_GetViewportYOffset(void)
{
    return lbl_803DC886;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_SetViewportYOffset(s16 yOffset)
{
    lbl_803DC886 = yOffset;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32* Camera_GetProjectionMatrix(void)
{
    return gCameraProjectionMatrix;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_RebuildProjectionMatrix(void)
{
    if (gCameraProjectionMode == 1) {
        C_MTXOrtho(gCameraProjectionMatrix, lbl_803DC8A0, lbl_803DC89C, lbl_803DC898,
                   lbl_803DC894, gCameraNearPlane, gCameraFarPlane);
    } else {
        C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio,
                         gCameraNearPlane, gCameraFarPlane);
        C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                              lbl_803DE628, lbl_803DE62C, lbl_803DE62C);
        C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                              lbl_803DE62C, lbl_803DE62C, lbl_803DE62C);
        C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                              lbl_803DE630, lbl_803DE62C, lbl_803DE62C);
    }
    GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 Camera_GetFarPlane(void)
{
    return gCameraFarPlane;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_SetFarPlane(f32 farPlane, int transitionFrames)
{
    if (transitionFrames != 0) {
        s16 frames = transitionFrames;
        lbl_803DC882 = frames;
        lbl_803DC880 = frames;
        lbl_803DC8AC = gCameraFarPlane;
        lbl_803DC8A8 = farPlane;
    } else {
        gCameraFarPlane = farPlane;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 Camera_GetNearPlane(void)
{
    return gCameraNearPlane;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 Camera_GetAspectRatio(void)
{
    return gCameraAspectRatio;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_SetAspectRatio(f32 aspectRatio)
{
    gCameraAspectRatio = aspectRatio;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 Camera_GetFovY(void)
{
    return gCameraFovY;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_SetFovY(f32 fovY)
{
    if (fovY == 0.0f) {
        fovY = 1.0f;
    }
    gCameraFovY = fovY;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Camera_InitState(void)
{
    u32 i;
    CameraViewSlot* slot;
    f32* scaledProjection;
    f32* copiedProjection;

    for (i = 0; i < 12; i++) {
        slot = &gCameraShakeSlots[(u8)i];
        slot->roll = 0;
        slot->yaw = 0;
        slot->pitch = 0x7FF8;
        slot->x = lbl_803DE650;
        slot->y = lbl_803DE650;
        slot->z = lbl_803DE650;
        *(f32*)((u8*)slot + 0x20) = lbl_803DE60C;
        *(f32*)((u8*)slot + 0x24) = lbl_803DE60C;
        *(f32*)((u8*)slot + 0x28) = lbl_803DE60C;
        slot->shakeMagnitude = lbl_803DE60C;
        *(u32*)((u8*)slot + 0x40) = 0;
        *(s16*)((u8*)slot + 0x5A) = 0;
        *(f32*)((u8*)slot + 0x18) = lbl_803DE610;
    }

    gCameraCurrentViewIndex = 0;
    lbl_803DC88C = 0;
    gObjTransformMatrixSlot = 0;
    lbl_803DC884 = 0;
    lbl_803DC886 = 0;
    gCameraFarPlane = lbl_803DE64C;
    lbl_803DC880 = 0;
    gCameraFovY = lbl_803DE610;
    gCameraProjectionMode = 0;

    if (gCameraProjectionMode == 1) {
        C_MTXOrtho(gCameraProjectionMatrix, lbl_803DC8A0, lbl_803DC89C, lbl_803DC898,
                   lbl_803DC894, gCameraNearPlane, gCameraFarPlane);
    } else {
        C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio, gCameraNearPlane,
                         gCameraFarPlane);
        C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                              lbl_803DE628, lbl_803DE62C, lbl_803DE62C);
        C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                              lbl_803DE62C, lbl_803DE62C, lbl_803DE62C);
        C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                              lbl_803DE630, lbl_803DE62C, lbl_803DE62C);
    }
    GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);

    scaledProjection = (f32*)((u8*)gObjInverseYawTransformMatrices + 0x1080);
    copiedProjection = (f32*)((u8*)gObjInverseYawTransformMatrices + 0x0FC0);
    matrixFn_8006ff0c(gCameraFovY, gCameraAspectRatio, gCameraNearPlane, gCameraFarPlane,
                      lbl_803DE5F0, scaledProjection, &lbl_803DC88A);
    copyMatrix44(scaledProjection, copiedProjection);
}
#pragma peephole reset
#pragma scheduling reset
