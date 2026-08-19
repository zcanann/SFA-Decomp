#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"

void Vec3_ReflectAgainstNormal(f32* normal, f32* velocity, f32* out)
{
    f32 yProduct = normal[1] * velocity[1];
    f32 dot = yProduct + normal[0] * velocity[0] + normal[2] * velocity[2];
    if (dot > 0.0f)
    {
        out[0] = velocity[0];
        out[1] = velocity[1];
        out[2] = velocity[2];
    }
    else
    {
        f32 reflectionScale = dot;
        reflectionScale *= -2.0f;
        out[0] = normal[0];
        out[1] = normal[1];
        out[2] = normal[2];
        out[0] *= reflectionScale;
        out[1] *= reflectionScale;
        out[2] *= reflectionScale;
        out[0] += velocity[0];
        out[1] += velocity[1];
        out[2] += velocity[2];
    }
}

void Vec3_ScaleAdd(const f32* base, const f32* vector, f32 scale, f32* out) {
    out[0] = scale * vector[0] + base[0];
    out[1] = scale * vector[1] + base[1];
    out[2] = scale * vector[2] + base[2];
}

f32 Vec3_Normalize(f32* vector) {
    f32 length = sqrtf(vector[0] * vector[0] + vector[1] * vector[1] + vector[2] * vector[2]);
    if (length != 0.0f) {
        f32 inverseLength = 1.0f / length;
        vector[0] *= inverseLength;
        vector[1] *= inverseLength;
        vector[2] *= inverseLength;
    }
    return length;
}

void Vec3_Cross(f32* lhs, f32* rhs, f32* out)
{
    out[0] = lhs[1] * rhs[2] - lhs[2] * rhs[1];
    out[1] = lhs[2] * rhs[0] - lhs[0] * rhs[2];
    out[2] = lhs[0] * rhs[1] - lhs[1] * rhs[0];
}

f32 Vec3_Length(const f32* vector)
{
    return sqrtf(vector[0] * vector[0] + vector[1] * vector[1] + vector[2] * vector[2]);
}
