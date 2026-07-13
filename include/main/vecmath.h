#ifndef MAIN_VECMATH_H_
#define MAIN_VECMATH_H_

#include "global.h"
#include "main/vecmath_distance_api.h"

typedef struct MatrixTransform
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} MatrixTransform;

STATIC_ASSERT(sizeof(MatrixTransform) == 0x18);

void Vec3_ScaleAdd(f32 *a, f32 *b, f32 s, f32 *out);
f32 Vec3_Length(f32 *v);
void Vec3_Cross(f32 *a, f32 *b, f32 *out);
void Vec3_ReflectAgainstNormal(f32 *normal, f32 *velocity, f32 *out);
f32 Vec3_Normalize(f32 *v);
f32 getXZDistance(f32* a, f32* b);
void mtx44ScaleRow1(f32* matrix, f32 scale);
void mtx44Transpose(f32* src, f32* dst);
void Matrix_TransformPoint(f32* matrix, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ);
void Matrix_TransformVector(f32* matrix, f32* vector, f32* out);
void copyMatrix44(f32* src, f32* dst);
void mtxRotateByVec3s(f32 *mtx, const void *transform);
void mtx44_multSafe(f32* lhs, f32* rhs, f32* out);
void setMatrixFromObjectPos(f32 *mtx, const MatrixTransform *transform);
int RandomTimer_UpdateRangeTrigger(void *timer, f32 lo, f32 hi);
int randomGetRange(int min, int max);
int getAngle(f32 deltaX, f32 deltaZ);

void vecRotateYXZ(s16* angles, f32* vector);
void vecRotateZXY(s16* rotation, f32* vector);
f32 interpolate(f32 a, f32 t, f32 exp);
void initRotationMtx(f32* mtx, f32 xScale, f32 yScale, f32 zScale);
void mtx44_mult(f32* a, f32* b, f32* out);
void setMatrixFromObjectTransposed(void* obj, f32* out);

#endif /* MAIN_VECMATH_H_ */
