#include "main/engine_shared.h"
#include "main/game_object.h"

f32 gObjInverseYawTransformMatrices[0x1E][16];
f32 gObjYawTransformMatrices[0x22][16];
u8 lbl_80338090[0x100];
f32 gCameraDefaultModelMatrix[16];
CameraViewSlot gCameraShakeSlots[0x480 / sizeof(CameraViewSlot)];
f32 gCameraViewRotationMatrix[16];
f32 gCameraInverseViewRotationMatrix[16];
f32 gCameraViewMatrix[16];
f32 gCameraInverseViewMatrix[16];
f32 gCameraProjectionMatrix[16];

void Obj_RotateLocalOffsetByYaw(f32* local, f32* out, s8 yawIndex)
{
    s32 matrixIndex;
    f32* matrix;

    if (yawIndex < 0)
    {
        out[0] = local[0];
        out[1] = local[1];
        out[2] = local[2];
    }
    else
    {
        matrixIndex = yawIndex << 4;
        matrix = (f32*)((u8*)gObjYawTransformMatrices + (matrixIndex << 2));
        Matrix_TransformPoint(matrix, local[0], local[1], local[2], &out[0], &out[1], &out[2]);
    }
}

void Obj_UpdateWorldTransform(s16* obj)
{
    s16* parent;
    s32 matrixIndex;
    f32* matrix;

    parent = *(s16**)(obj + 0x20);
    if (parent == 0)
    {
        *(f32*)(obj + 0x22) = ((GameObject*)obj)->anim.localPosX;
        *(f32*)(obj + 0x24) = ((GameObject*)obj)->anim.localPosY;
        *(f32*)(obj + 0x26) = ((GameObject*)obj)->anim.localPosZ;
        obj[0x28] = obj[0];
        obj[0x29] = obj[1];
        obj[0x2A] = obj[2];
    }
    else
    {
        matrixIndex = *(s8*)((u8*)parent + 0x35) << 4;
        matrix = (f32*)((u8*)gObjYawTransformMatrices + (matrixIndex << 2));
        Matrix_TransformPoint(matrix, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                              (f32*)(obj + 0x22), (f32*)(obj + 0x24), (f32*)(obj + 0x26));
        obj[0x28] = obj[0] - parent[0];
        obj[0x29] = obj[1];
        obj[0x2A] = obj[2];
    }
}

s32 Angle_AddWrappedS16(s32 angle, s16* delta)
{
    if ((angle += *delta) > 0x8000)
    {
        angle -= 0xFFFF;
    }
    if (angle >= -0x8000)
    {
        return angle;
    }
    return angle + 0xFFFF;
}

s32 Angle_SubWrappedS16(s32 angle, s16* delta)
{
    if ((angle -= *delta) > 0x8000)
    {
        angle -= 0xFFFF;
    }
    if (angle >= -0x8000)
    {
        return angle;
    }
    return angle + 0xFFFF;
}

void Obj_TransformLocalVectorToWorld(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, u32 obj)
{
    f32 vec[3];
    s32 matrixIndex;

    vec[0] = x;
    vec[1] = y;
    vec[2] = z;
    matrixIndex = *(s8*)(obj + 0x35) << 4;
    Matrix_TransformVector((f32*)((u8*)gObjYawTransformMatrices + (matrixIndex << 2)), vec, vec);
    *outX = vec[0];
    *outY = vec[1];
    *outZ = vec[2];
}

void Obj_TransformWorldVectorToLocal(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, u32 obj)
{
    f32 vec[3];
    s32 matrixIndex;

    vec[0] = x;
    vec[1] = y;
    vec[2] = z;
    matrixIndex = *(s8*)(obj + 0x35) << 4;
    Matrix_TransformVector((f32*)((u8*)gObjInverseYawTransformMatrices + (matrixIndex << 2)), vec, vec);
    *outX = vec[0];
    *outY = vec[1];
    *outZ = vec[2];
}

void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, u32 obj)
{
    s32 matrixIndex;

    if (obj != 0)
    {
        matrixIndex = *(s8*)(obj + 0x35) << 4;
        Matrix_TransformPoint((f32*)((u8*)gObjInverseYawTransformMatrices + (matrixIndex << 2)), x, y, z, outX, outY,
                              outZ);
    }
    else
    {
        *outX = x;
        *outY = y;
        *outZ = z;
    }
}

void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, u32 obj)
{
    s32 matrixIndex;

    if (obj != 0)
    {
        matrixIndex = *(s8*)(obj + 0x35) << 4;
        Matrix_TransformPoint((f32*)((u8*)gObjYawTransformMatrices + (matrixIndex << 2)), x, y, z, outX, outY, outZ);
    }
    else
    {
        *outX = x;
        *outY = y;
        *outZ = z;
    }
}

void Obj_GetWorldPosition(u32 obj, f32* outX, f32* outY, f32* outZ)
{
    u32 parent;
    s32 matrixIndex;

    parent = *(u32*)&((GameObject*)obj)->anim.parent;
    if (parent == 0)
    {
        *outX = ((GameObject*)obj)->anim.localPosX;
        *outY = ((GameObject*)obj)->anim.localPosY;
        *outZ = ((GameObject*)obj)->anim.localPosZ;
    }
    else
    {
        matrixIndex = *(s8*)(parent + 0x35) << 4;
        Matrix_TransformPoint((f32*)((u8*)gObjYawTransformMatrices + (matrixIndex << 2)),
                              ((GameObject*)obj)->anim.localPosX,
                              ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ, outX, outY, outZ);
    }
}

void Obj_BuildTransformMatricesForYaw(u32 obj, s32 yawIndex)
{
    u8* base;
    u32 ancestors[4];
    ObjMatrixBuildTransform inverseTransform;
    u32 current;
    s32 matrixIndex;
    f32* yawMatrix;
    f32* inverseYawMatrix;
    f32 savedScale;
    s8 ancestorCount;
    s8 hasParent;

    current = obj;
    base = (u8*)gObjInverseYawTransformMatrices;
    matrixIndex = yawIndex << 4;
    yawMatrix = (f32*)(base + ((matrixIndex << 2) + 1920));
    inverseYawMatrix = (f32*)(base + (matrixIndex << 2));
    hasParent = 0;
    ancestorCount = 0;
    while (current != 0)
    {
        ancestors[ancestorCount] = current;
        ancestorCount++;
        savedScale = ((GameObject*)current)->anim.rootMotionScale;
        if ((((GameObject*)current)->objectFlags & 8) == 0)
        {
            ((GameObject*)current)->anim.rootMotionScale = lbl_803DE5F0;
        }

        if (hasParent == 0)
        {
            setMatrixFromObjectPos(yawMatrix, (void*)current);
        }
        else
        {
            setMatrixFromObjectPos((f32*)(base + 3904), (void*)current);
            mtx44_multSafe(yawMatrix, (f32*)(base + 3904), yawMatrix);
        }

        ((GameObject*)current)->anim.rootMotionScale = savedScale;
        current = (u32)((GameObject*)current)->anim.parent;
        hasParent = 1;
    }

    while (ancestorCount > 0)
    {
        ancestorCount--;
        current = ancestors[ancestorCount];
        inverseTransform.x = -((GameObject*)current)->anim.localPosX;
        inverseTransform.y = -((GameObject*)current)->anim.localPosY;
        inverseTransform.z = -((GameObject*)current)->anim.localPosZ;
        if ((((GameObject*)current)->objectFlags & 8) == 0)
        {
            inverseTransform.scale = lbl_803DE5F0;
        }
        else
        {
            inverseTransform.scale = lbl_803DE5F0 / ((GameObject*)current)->anim.rootMotionScale;
        }
        inverseTransform.rotX = -((GameObject*)current)->anim.rotX;
        inverseTransform.rotY = -((GameObject*)current)->anim.rotY;
        inverseTransform.rotZ = -((GameObject*)current)->anim.rotZ;
        mtxRotateByVec3s(inverseYawMatrix, &inverseTransform);
    }
}

void Obj_BuildTransformMatrices(u32 obj)
{
    Obj_BuildTransformMatricesForYaw(obj, *(s8*)(obj + 0x35));
}

s32 Obj_BuildTransformMatrixSlot(u32 obj)
{
    Obj_BuildTransformMatricesForYaw(obj, gObjTransformMatrixSlot);
    gObjTransformMatrixSlot++;
    return gObjTransformMatrixSlot - 1;
}

f32* Camera_GetViewRotationMatrix(void)
{
    return gCameraViewRotationMatrix;
}

f32* Camera_GetInverseViewRotationMatrix(void)
{
    return gCameraInverseViewRotationMatrix;
}

f32* Camera_GetViewMatrix(void)
{
    return gCameraViewMatrix;
}

f32* Camera_GetInverseViewMatrix(void)
{
    return gCameraInverseViewMatrix;
}

void* Camera_GetCurrentViewSlot(void)
{
    return &gCameraShakeSlots[gCameraCurrentViewIndex];
}

u8 CameraShake_IsActive(void)
{
    s32 offset = gCameraCurrentViewIndex * sizeof(CameraViewSlot);
    CameraViewSlot* slot = (CameraViewSlot*)((u8*)gCameraShakeSlots + offset);

    return slot->shakeActive == 1;
}

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

void CameraShake_SetAllMagnitudes(f32 magnitude)
{
    CameraViewSlot* slot = gCameraShakeSlots;
    int group;
    int i;

    for (group = 0; group < 2; group++)
    {
        for (i = 0; i < 6; i++)
        {
            CameraViewSlot* p = &slot[i];
            p->shakeMagnitude = magnitude;
            p->shakeActive = 0;
        }
        slot += 6;
    }
}

void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 magnitude)
{
    CameraViewSlot* slot;
    s32 i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    s8 inactive;

    slot = gCameraShakeSlots;
    inactive = 0;
    for (i = 0; i <= 7; i++)
    {
        dx = x - slot[i].x;
        dy = y - slot[i].y;
        dz = z - slot[i].z;
        distance = sqrtf(dx * dx + dy * dy + dz * dz);
        if (distance < radius)
        {
            slot[i].shakeMagnitude = (magnitude * (radius - distance)) / radius;
            slot[i].shakeActive = inactive;
        }
    }
}

void* fn_8000E814(void)
{
    return lbl_80338090;
}

void Camera_LoadModelViewMatrix(void* unused0, void* unused1, CameraViewSlot* transform, f32 scale, f32* matrix)
{
    f32* modelMatrix;

    if (matrix != NULL)
    {
        modelMatrix = matrix;
    }
    else
    {
        modelMatrix = gCameraDefaultModelMatrix;
    }

    transform->x -= playerMapOffsetX;
    transform->z -= playerMapOffsetZ;
    setMatrixFromObjectPos(modelMatrix, transform);
    if (lbl_803DE5F0 != scale)
    {
        mtx44ScaleRow1(modelMatrix, scale);
    }

    if (matrix == NULL)
    {
        mtx44Transpose(modelMatrix, lbl_803967C0);
    }
    else
    {
        mtx44Transpose(matrix, lbl_803967C0);
    }

    PSMTXConcat(gCameraViewMatrix, lbl_803967C0, lbl_803967C0);
    GXLoadPosMtxImm(lbl_803967C0, 0);
    transform->x += playerMapOffsetX;
    transform->z += playerMapOffsetZ;
}

void Camera_NdcToScreen(f32 ndcX, f32 ndcY, f32 ndcZ, s32* outX, s32* outY, s32* outZ)
{
    f32 coord;

    if (outX != NULL)
    {
        coord = ndcX * (f32)(gCameraViewportScreenParams[0] >> 2);
        coord = coord + (f32)(gCameraViewportScreenParams[4] >> 2);
        *outX = coord;
    }

    if (outY != NULL)
    {
        coord = ndcY * (f32)(gCameraViewportScreenParams[1] >> 2);
        coord = coord + (f32)(gCameraViewportScreenParams[5] >> 2);
        *outY = coord;
        *outY = 0x1E0 - *outY;
    }

    if (outZ != NULL)
    {
        *outZ = (s32)(gCameraDepth24BitMax * (lbl_803DE5F0 + ndcZ));
    }
}

void screenFn_8000e944(void* viewportArg)
{
    u32 resolution;
    u32 width;
    u32* viewportFlags;
    u32 height;
    u8 viewIndex;
    u32 halfHeight;

    gCameraCurrentViewIndex = 4;
    resolution = getScreenResolution();
    width = resolution >> 16;
    height = resolution & 0xFFFF;
    viewportFlags = (u32*)(gCameraViewportEntries + 0x30);

    if ((*(int*)((u8*)viewportFlags + gCameraCurrentViewIndex * 0x34) & 1) == 0)
    {
        gxSetScissorRect(0, 0, 0, 0, height - 1, width - 1);
        halfHeight = height >> 1;
        viewIndex = gCameraCurrentViewIndex;
        if ((*(int*)((u8*)viewportFlags + viewIndex * 0x34) & 1) == 0)
        {
            s16 halfWidth;
            gCameraViewportScreenParams[viewIndex * 8 + 4] = (s16)(halfHeight << 2);
            halfWidth = (s16)((width >> 1) << 2);
            gCameraViewportScreenParams[viewIndex * 8 + 5] = halfWidth;
            gCameraViewportScreenParams[viewIndex * 8 + 0] = (s16)(halfHeight << 2);
            gCameraViewportScreenParams[viewIndex * 8 + 1] = halfWidth;
        }
    }
    else
    {
        Camera_ApplyCurrentViewport(viewportArg);
        viewIndex = gCameraCurrentViewIndex;
        if ((*(int*)((u8*)viewportFlags + viewIndex * 0x34) & 1) == 0)
        {
            gCameraViewportScreenParams[viewIndex * 8 + 4] = 0;
            gCameraViewportScreenParams[viewIndex * 8 + 5] = 0;
            gCameraViewportScreenParams[viewIndex * 8 + 0] = 0;
            gCameraViewportScreenParams[viewIndex * 8 + 1] = 0;
        }
    }

    gCameraCurrentViewIndex = 0;
}

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
    (gCameraProjectionMatrix[0] * pos[0] +
        gCameraProjectionMatrix[1] * pos[1] +
        gCameraProjectionMatrix[2] * pos[2]);
    *outY = gCameraProjectionMatrix[7] +
    (gCameraProjectionMatrix[4] * pos[0] +
        gCameraProjectionMatrix[5] * pos[1] +
        gCameraProjectionMatrix[6] * pos[2]);
    *outZ = gCameraProjectionMatrix[11] +
    (gCameraProjectionMatrix[8] * pos[0] +
        gCameraProjectionMatrix[9] * pos[1] +
        gCameraProjectionMatrix[10] * pos[2]);

    w = gCameraProjectionMatrix[15] +
    (gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1] +
        gCameraProjectionMatrix[14] * pos[2]);
    if (lbl_803DE60C != w)
    {
        invW = lbl_803DE5F0 / w;
        *outX *= invW;
        *outY *= invW;
        *outZ *= invW;
    }
}

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
    (gCameraProjectionMatrix[0] * pos[0] +
        gCameraProjectionMatrix[1] * pos[1] +
        gCameraProjectionMatrix[2] * pos[2]);
    *outY = gCameraProjectionMatrix[7] +
    (gCameraProjectionMatrix[4] * pos[0] +
        gCameraProjectionMatrix[5] * pos[1] +
        gCameraProjectionMatrix[6] * pos[2]);
    *outZ = gCameraProjectionMatrix[11] +
    (gCameraProjectionMatrix[8] * pos[0] +
        gCameraProjectionMatrix[9] * pos[1] +
        gCameraProjectionMatrix[10] * pos[2]);

    w = gCameraProjectionMatrix[15] +
    (gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1] +
        gCameraProjectionMatrix[14] * pos[2]);
    if (lbl_803DE60C != w)
    {
        invW = lbl_803DE5F0 / w;
        *outX *= invW;
        *outY *= invW;
        *outZ *= invW;
    }
}

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
    (gCameraProjectionMatrix[0] * pos[0] +
        gCameraProjectionMatrix[1] * pos[1] +
        gCameraProjectionMatrix[2] * pos[2]);
    *outY = gCameraProjectionMatrix[7] +
    (gCameraProjectionMatrix[4] * pos[0] +
        gCameraProjectionMatrix[5] * pos[1] +
        gCameraProjectionMatrix[6] * pos[2]);
    *outZ = gCameraProjectionMatrix[11] +
    (gCameraProjectionMatrix[8] * pos[0] +
        gCameraProjectionMatrix[9] * pos[1] +
        gCameraProjectionMatrix[10] * pos[2]);

    w = gCameraProjectionMatrix[15] +
    (gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1] +
        gCameraProjectionMatrix[14] * pos[2]);
    if (lbl_803DE60C != w)
    {
        invW = lbl_803DE5F0 / w;
        *outX *= invW;
        *outY *= invW;
        *outZ *= invW;

        pos[2] += radius;
        if (pos[2] > *(f32*)&lbl_803DE624)
        {
            pos[2] = lbl_803DE624;
        }

        w = gCameraProjectionMatrix[15] +
        (gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1] +
            gCameraProjectionMatrix[14] * pos[2]);
        if (lbl_803DE60C != w)
        {
            invW = lbl_803DE5F0 / w;
            *outRadiusX = fabsf(invW * (radius * gCameraProjectionMatrix[0]));
            *outRadiusY = fabsf(invW * (radius * gCameraProjectionMatrix[5]));
            *outRadiusZ = fabsf(invW * (radius * gCameraProjectionMatrix[10]));
        }
    }
}

void viewportEffectFn_8000e380(void)
{
    CameraViewSlot* slot;
    f32 expTerm;
    f32 one;
    f32 factorial;
    f32 n;
    f32 term;
    f32 falloffTime;
    f32 shakeTimer;
    f32 sinePhase;
    f32 phaseScale;
    s32 i;

    gCameraViewportYOffset = cameraViewportYOffset;
    if (gCameraFarPlaneTransitionFramesLeft != 0)
    {
        gCameraFarPlaneTransitionFramesLeft -= framesThisStep;
        if (gCameraFarPlaneTransitionFramesLeft < 0)
        {
            gCameraFarPlaneTransitionFramesLeft = 0;
        }
        gCameraFarPlane = ((f32)gCameraFarPlaneTransitionFramesLeft / gCameraFarPlaneTransitionFrames) * (gCameraFarPlaneTransitionStart - gCameraFarPlaneTransitionTarget) + gCameraFarPlaneTransitionTarget;
    }

    gObjTransformMatrixSlot = 0;
    slot = &gCameraShakeSlots[gCameraCurrentViewIndex];

    if (slot->shakeActive == 0)
    {
        slot->shakeFlipTimer--;
        while (slot->shakeFlipTimer < 0)
        {
            slot->shakeFlipTimer++;
            slot->shakeMagnitude = gCameraShakeMagnitudeDecay * -slot->shakeMagnitude;
        }
    }
    else if (slot->shakeActive == 1)
    {
        falloffTime = -slot->shakeFalloff * (shakeTimer = slot->shakeTimer);
        expTerm = *(f32*)&lbl_803DE5F0;
        n = expTerm;
        term = falloffTime;
        factorial = expTerm;
        one = expTerm;

        for (i = 0; i < 2; i++)
        {
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

        phaseScale = lbl_803DE5FC * slot->shakeDuration;
        sinePhase = (gCameraPi * (phaseScale * shakeTimer)) / lbl_803DE600;
        slot->shakeMagnitude = slot->shakeMagnitudeTarget * expTerm * mathCosf(sinePhase);
        if ((slot->shakeMagnitude < gCameraShakeStopThreshold) && (slot->shakeMagnitude > gCameraShakeStopThresholdNeg))
        {
            slot->shakeMagnitude = lbl_803DE60C;
            slot->shakeActive = -1;
        }
        slot->shakeTimer += timeDelta / lbl_803DE610;
    }
}

#pragma dont_inline on
void Camera_ApplyCurrentViewport(void* viewportArg)
{
    u16 height;
    int viewportY;
    u32 clipped;

    clipped = getScreenResolution();
    viewportY = clipped >> 16;
    height = clipped;
    clipped = viewportY;
    viewportY = gCameraViewportYOffset + 6;
    clipped = clipped - viewportY;
    gxSetScissorRect(0, 0, 0, viewportY, height, clipped);
}
#pragma dont_inline reset

#pragma opt_common_subs off
void Camera_UpdateProjection(void* viewportArg)
{
    u8 viewIndex = gCameraCurrentViewIndex;
    u8 activeViewIndex;
    u32 resolution = getScreenResolution();
    u32 screenHeight = resolution & 0xffff;
    u32 screenWidth = resolution >> 16;
    u8* base = gCameraViewportEntries;
    u8* viewportEntry = base + viewIndex * 0x34;

    if ((*(int*)(viewportEntry + 0x30) & 1) != 0)
    {
        u8 savedViewIndex = gCameraCurrentViewIndex;

        gCameraCurrentViewIndex = viewIndex;
        viewportEntry = base + (viewIndex & 0xff) * 0x34;
        gxSetScissorRect(0, 0,
                         *(s32*)(viewportEntry + 0x20),
                         *(s32*)(viewportEntry + 0x24),
                         *(s32*)(viewportEntry + 0x28),
                         *(s32*)(viewportEntry + 0x2c));

        viewportEntry = gCameraViewportEntries;
        viewportEntry += gCameraCurrentViewIndex * 0x34;
        if ((*(int*)(viewportEntry + 0x30) & 1) == 0)
        {
            activeViewIndex = gCameraCurrentViewIndex;
            gCameraViewportScreenParams[activeViewIndex * 8 + 4] = 0;
            gCameraViewportScreenParams[activeViewIndex * 8 + 5] = 0;
            gCameraViewportScreenParams[activeViewIndex * 8 + 0] = 0;
            gCameraViewportScreenParams[activeViewIndex * 8 + 1] = 0;
        }

        gCameraCurrentViewIndex = savedViewIndex;
        if (gCameraProjectionMode == 1)
        {
            C_MTXOrtho(gCameraProjectionMatrix, gCameraOrthoTop, gCameraOrthoBottom, gCameraOrthoLeft,
                       gCameraOrthoRight, gCameraNearPlane, gCameraFarPlane);
        }
        else
        {
            C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio,
                             gCameraNearPlane, gCameraFarPlane);
            C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                                  *(f32*)&lbl_803DE628, lbl_803DE62C, *(f32*)&lbl_803DE62C);
            C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  *(f32*)&lbl_803DE62C, *(f32*)&lbl_803DE62C, *(f32*)&lbl_803DE62C);
            C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE630, *(f32*)&lbl_803DE62C, *(f32*)&lbl_803DE62C);
        }
        GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
        gCameraCurrentViewIndex = viewIndex;
    }
    else
    {
        u32 halfScreenHeight = screenHeight >> 1;
        u32 halfScreenWidth = screenWidth >> 1;

        activeViewIndex = gCameraCurrentViewIndex;
        viewportEntry = gCameraViewportEntries;
        viewportEntry += activeViewIndex * 0x34;
        if ((*(int*)(viewportEntry + 0x30) & 1) == 0)
        {
            s16 scaledHalfHeight;
            s16 scaledHalfWidth;

            scaledHalfHeight = (s16)(halfScreenHeight << 2);
            gCameraViewportScreenParams[activeViewIndex * 8 + 4] = scaledHalfHeight;
            scaledHalfWidth = (s16)(halfScreenWidth << 2);
            gCameraViewportScreenParams[activeViewIndex * 8 + 5] = scaledHalfWidth;
            gCameraViewportScreenParams[activeViewIndex * 8 + 0] = scaledHalfHeight;
            gCameraViewportScreenParams[activeViewIndex * 8 + 1] = scaledHalfWidth;
        }

        if (gCameraProjectionMode == 1)
        {
            C_MTXOrtho(gCameraProjectionMatrix, gCameraOrthoTop, gCameraOrthoBottom, gCameraOrthoLeft,
                       gCameraOrthoRight, gCameraNearPlane, gCameraFarPlane);
        }
        else
        {
            C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio,
                             gCameraNearPlane, gCameraFarPlane);
            C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                                  *(f32*)&lbl_803DE628, lbl_803DE62C, *(f32*)&lbl_803DE62C);
            C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  *(f32*)&lbl_803DE62C, *(f32*)&lbl_803DE62C, *(f32*)&lbl_803DE62C);
            C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE630, *(f32*)&lbl_803DE62C, *(f32*)&lbl_803DE62C);
        }
        GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
        Camera_ApplyCurrentViewport(viewportArg);
        gCameraCurrentViewIndex = viewIndex;
    }
}
#pragma opt_common_subs reset

void Camera_GetCurrentViewport(s32* outX, s32* outY, u32* outHeight, s32* outWidth)
{
    u32 resolution = getScreenResolution();

    *outX = 0;
    *outHeight = resolution & 0xffff;
    *outY = gCameraViewportYOffset + 6;
    *outWidth = (resolution >> 16) - (gCameraViewportYOffset + 6);
}

void Camera_SetCurrentViewIndex(int index)
{
    if (index >= 0 && index < 4)
    {
        gCameraCurrentViewIndex = index;
        return;
    }
    gCameraCurrentViewIndex = 0;
}

f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];
    f32 delta;
    f32 dz;
    f32 dx;
    f32 dy;

    delta = z - slot->z;
    dz = delta * delta;
    delta = x - slot->x;
    dx = delta * delta;
    delta = y - slot->y;
    dy = delta * delta;
    return sqrtf(dz + (dx + dy));
}

void Camera_SetCurrentViewRotation(int pitch, int yaw, int roll)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];

    slot->pitch = pitch;
    slot->yaw = yaw;
    slot->roll = roll;
}

void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];

    slot->x = x;
    slot->y = y;
    slot->z = z;
}

#pragma optimization_level 2
void Camera_UpdateViewMatrices(void)
{
    u8* base = (u8*)gObjInverseYawTransformMatrices;
    CameraViewSlot* slot;
    CameraMatrixTransform transform;
    f32 rotationMatrix[16];

    slot = (CameraViewSlot*)(base + gCameraCurrentViewIndex * 96);
    slot = (CameraViewSlot*)((u8*)slot + 4416);
    transform.x = -(slot->x - playerMapOffsetX);
    transform.y = -slot->y;
    transform.z = -(slot->z - playerMapOffsetZ);
    transform.pitch = slot->pitch + 0x8000;
    transform.yaw = slot->yaw;
    transform.roll = slot->roll;
    transform.scale = lbl_803DE5F0;
    if (pauseMenuGetState() == 0)
    {
        if (cameraViewYOffsetEnabled != 0)
        {
            transform.y -= slot->shakeMagnitude;
        }
        transform.x += lbl_803DE60C;
        transform.y += lbl_803DE60C;
        transform.z += lbl_803DE60C;
    }

    mtxRotateByVec3s(rotationMatrix, &transform);
    mtx44Transpose(rotationMatrix, (f32*)(base + 5696));

    transform.x = slot->x - playerMapOffsetX;
    transform.y = slot->y;
    transform.z = slot->z - playerMapOffsetZ;
    transform.pitch = -(slot->pitch + 0x8000);
    transform.yaw = -slot->yaw;
    transform.roll = -slot->roll;
    transform.scale = lbl_803DE5F0;
    if (pauseMenuGetState() == 0)
    {
        if (cameraViewYOffsetEnabled != 0)
        {
            transform.y += slot->shakeMagnitude;
        }
        transform.x -= lbl_803DE60C;
        transform.y -= lbl_803DE60C;
        transform.z -= lbl_803DE60C;
    }

    setMatrixFromObjectPos((f32*)(base + 4096), &transform);
    mtx44Transpose((f32*)((int)base + 4096), (f32*)(base + 5760));
    PSMTXCopy((f32*)(base + 5696), (f32*)(base + 5568));
    *(f32*)(base + 5568 + 44) = *(f32*)(base + 5568 + 28) = *(f32*)(base + 5568 + 12) = lbl_803DE60C;
    PSMTXCopy((f32*)(base + 5760), (f32*)(base + 5632));
    *(f32*)(base + 5632 + 44) = *(f32*)(base + 5632 + 28) = *(f32*)(base + 5632 + 12) = lbl_803DE60C;
}
#pragma optimization_level reset

void Camera_ApplyFullViewport(void)
{
    CameraRenderMode* renderMode = gRenderModeObj;

    if (renderMode->useViewportJitter != 0)
    {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, renderMode->fbWidth,
                            renderMode->xfbHeight, lbl_803DE60C, lbl_803DE5F0,
                            lbl_803DCCBC);
    }
    else
    {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, renderMode->fbWidth,
                      renderMode->xfbHeight, lbl_803DE60C, lbl_803DE5F0);
    }
}

void fn_8000F83C(void)
{
    CameraRenderMode* renderMode = gRenderModeObj;

    if (renderMode->useViewportJitter != 0)
    {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, renderMode->fbWidth,
                            renderMode->xfbHeight, lbl_803DE640, lbl_803DE5F0,
                            lbl_803DCCBC);
    }
    else
    {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, renderMode->fbWidth,
                      renderMode->xfbHeight, lbl_803DE640, lbl_803DB26C);
    }
}

void fn_8000F8F8(void)
{
    CameraRenderMode* renderMode = gRenderModeObj;

    if (renderMode->useViewportJitter != 0)
    {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, renderMode->fbWidth,
                            renderMode->xfbHeight, lbl_803DE644, lbl_803DE5F0,
                            lbl_803DCCBC);
    }
    else
    {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, renderMode->fbWidth,
                      renderMode->xfbHeight, lbl_803DE644, lbl_803DE5F0);
    }
}

void fn_8000F9B4(void)
{
    CameraRenderMode* renderMode = gRenderModeObj;

    if (renderMode->useViewportJitter != 0)
    {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, renderMode->fbWidth,
                            renderMode->xfbHeight, lbl_803DE648, lbl_803DE5F0,
                            lbl_803DCCBC);
    }
    else
    {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, renderMode->fbWidth,
                      renderMode->xfbHeight, lbl_803DE648, lbl_803DE5F0);
    }
}

u16 fn_8000FA70(void)
{
    return gCameraShakeSlots[gCameraCurrentViewIndex].yaw;
}

u16 fn_8000FA90(void)
{
    return gCameraShakeSlots[gCameraCurrentViewIndex].pitch;
}

u8 Camera_IsViewYOffsetEnabled(void)
{
    return cameraViewYOffsetEnabled;
}

void Camera_DisableViewYOffset(void)
{
    cameraViewYOffsetEnabled = 0;
}

void Camera_EnableViewYOffset(void)
{
    cameraViewYOffsetEnabled = 1;
}

s16 Camera_GetViewportYOffset(void)
{
    return cameraViewportYOffset;
}

void Camera_SetViewportYOffset(s16 yOffset)
{
    cameraViewportYOffset = yOffset;
}

f32* Camera_GetProjectionMatrix(void)
{
    return gCameraProjectionMatrix;
}

#pragma opt_common_subs off
void Camera_RebuildProjectionMatrix(void)
{
    if (gCameraProjectionMode == 1)
    {
        C_MTXOrtho(gCameraProjectionMatrix, gCameraOrthoTop, gCameraOrthoBottom, gCameraOrthoLeft,
                   gCameraOrthoRight, gCameraNearPlane, gCameraFarPlane);
    }
    else
    {
        C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio,
                         gCameraNearPlane, gCameraFarPlane);
        C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                              *(f32*)&lbl_803DE628, lbl_803DE62C, *(f32*)&lbl_803DE62C);
        C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                              *(f32*)&lbl_803DE62C, *(f32*)&lbl_803DE62C, *(f32*)&lbl_803DE62C);
        C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                              lbl_803DE630, *(f32*)&lbl_803DE62C, *(f32*)&lbl_803DE62C);
    }
    GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
}
#pragma opt_common_subs reset

f32 Camera_GetFarPlane(void)
{
    return gCameraFarPlane;
}

void Camera_SetFarPlane(f32 farPlane, int transitionFrames)
{
    if (transitionFrames != 0)
    {
        s16 frames = transitionFrames;
        gCameraFarPlaneTransitionFrames = frames;
        gCameraFarPlaneTransitionFramesLeft = frames;
        gCameraFarPlaneTransitionStart = gCameraFarPlane;
        gCameraFarPlaneTransitionTarget = farPlane;
    }
    else
    {
        gCameraFarPlane = farPlane;
    }
}

f32 Camera_GetNearPlane(void)
{
    return gCameraNearPlane;
}

f32 Camera_GetAspectRatio(void)
{
    return gCameraAspectRatio;
}

void Camera_SetAspectRatio(f32 aspectRatio)
{
    gCameraAspectRatio = aspectRatio;
}

f32 Camera_GetFovY(void)
{
    return gCameraFovY;
}

void Camera_SetFovY(f32 fovY)
{
    if (fovY == 0.0f)
    {
        fovY = 1.0f;
    }
    gCameraFovY = fovY;
}

#pragma ppc_unroll_speculative on
#pragma ppc_unroll_factor_limit 3
#pragma ppc_unroll_instructions_limit 80
void Camera_InitState(void)
{
    u8* base = (u8*)gObjInverseYawTransformMatrices;
    u32 i;
    CameraViewSlot* slot;

    for (i = 0; i < 12; i++)
    {
        slot = (CameraViewSlot*)(base + (u8)i * 96);
        slot = (CameraViewSlot*)((u8*)slot + 4416);
        slot->roll = 0;
        slot->yaw = 0;
        slot->pitch = 0x7FF8;
        slot->x = gCameraDefaultPosition;
        slot->y = gCameraDefaultPosition;
        slot->z = gCameraDefaultPosition;
        *(f32*)((u8*)slot + 0x20) = lbl_803DE60C;
        *(f32*)((u8*)slot + 0x24) = lbl_803DE60C;
        *(f32*)((u8*)slot + 0x28) = lbl_803DE60C;
        slot->shakeMagnitude = lbl_803DE60C;
        *(u32*)((u8*)slot + 0x40) = 0;
        *(s16*)((u8*)slot + 0x5A) = 0;
        *(f32*)((u8*)slot + 0x18) = lbl_803DE610;
    }

    gCameraCurrentViewIndex = 0;
    cameraViewYOffsetEnabled = 0;
    gObjTransformMatrixSlot = 0;
    gCameraViewportYOffset = 0;
    cameraViewportYOffset = 0;
    gCameraFarPlane = gCameraDefaultFarPlane;
    gCameraFarPlaneTransitionFramesLeft = 0;
    gCameraFovY = lbl_803DE610;
    gCameraProjectionMode = 0;

    if (gCameraProjectionMode == 1)
    {
        C_MTXOrtho((f32*)(base + 5824), gCameraOrthoTop, gCameraOrthoBottom, gCameraOrthoLeft,
                   gCameraOrthoRight, gCameraNearPlane, gCameraFarPlane);
    }
    else
    {
        C_MTXPerspective((f32*)(base + 5824), gCameraFovY, gCameraAspectRatio, gCameraNearPlane,
                         gCameraFarPlane);
        C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                              *(f32*)&lbl_803DE628, 0.5f, 0.5f);
        C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, 0.5f, 0.5f, 0.5f, 0.5f);
        C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, 0.5f, lbl_803DE630,
                              0.5f, 0.5f);
    }
    GXSetProjection((f32*)(base + 5824), gCameraProjectionMode);

    matrixFn_8006ff0c((f32*)(base + 0x1080), &lbl_803DC88A, gCameraFovY, gCameraAspectRatio,
                      gCameraNearPlane, gCameraFarPlane, lbl_803DE5F0);
    copyMatrix44((f32*)((int)base + 0x1080), (f32*)(base + 0x0FC0));
}

u8 gCameraViewportEntries[208] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 64, 0, 0, 0, 240,
    0, 0, 0, 160, 0, 0, 0, 120, 0, 0, 1, 64, 0, 0, 0, 240,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 63, 0, 0, 0, 239,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 64,
    0, 0, 0, 240, 0, 0, 0, 160, 0, 0, 0, 120, 0, 0, 1, 64,
    0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 63,
    0, 0, 0, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 64, 0, 0, 0, 240, 0, 0, 0, 160, 0, 0, 0, 120,
    0, 0, 1, 64, 0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 63, 0, 0, 0, 239, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 64, 0, 0, 0, 240, 0, 0, 0, 160,
    0, 0, 0, 120, 0, 0, 1, 64, 0, 0, 0, 240, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 63, 0, 0, 0, 239, 0, 0, 0, 0,
};

s16 gCameraViewportScreenParams[160] = {
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
    0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0, 0, 0, 511, 0,
};
