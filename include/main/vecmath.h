#ifndef MAIN_VECMATH_H_
#define MAIN_VECMATH_H_

#include "global.h"

void Vec3_ScaleAdd(f32 *a, f32 s, f32 *b, f32 *out);
f32 Vec3_Length(f32 *v);
void Vec3_Cross(f32 *a, f32 *b, f32 *out);
void Vec3_ReflectAgainstNormal(f32 *normal, f32 *velocity, f32 *out);
f32 Vec3_Normalize(f32 *v);

#endif /* MAIN_VECMATH_H_ */
