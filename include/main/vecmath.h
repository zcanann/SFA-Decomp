#ifndef MAIN_VECMATH_H_
#define MAIN_VECMATH_H_

#include "global.h"

void Vec3_ScaleAdd(f32 *a, f32 *b, f32 s, f32 *out);
f32 Vec3_Length(f32 *v);
void Vec3_Cross(f32 *a, f32 *b, f32 *out);
void Vec3_ReflectAgainstNormal(f32 *normal, f32 *velocity, f32 *out);
f32 Vec3_Normalize(f32 *v);
void mtxRotateByVec3s(f32 *mtx, void *transform);
void setMatrixFromObjectPos(f32 *mtx, void *transform);
int RandomTimer_UpdateRangeTrigger(void *timer, f32 lo, f32 hi);

void vecRotateYXZ(int, int);
f32 interpolate(f32 a, f32 t, f32 exp);
void initRotationMtx(f32* mtx, f32 xScale, f32 yScale, f32 zScale);
void mtx44_mult(f32* a, f32* b, f32* out);
void setMatrixFromObjectTransposed(void* obj, f32* out);

#endif /* MAIN_VECMATH_H_ */
