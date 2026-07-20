#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/k_tan.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

extern float lbl_803E7AB8;
extern float lbl_803E7BC8;
extern float lbl_803E7BF4;
extern float lbl_803E7BF8;

#pragma optimization_level 0
#pragma optimize_for_size on
float powfBitEstimate(float base, float exponentValue) {
    u32 baseBits;
    float result;
    float normalizedMantissa;
    s16 exponent;
    float exponentAsFloat;
    int integerPower;

    if (base != lbl_803E7AB8) {
        baseBits = *(u32 *)&base;
        exponent = (s16)(((baseBits >> 23) & 0xFF) - 128);
        *(u32 *)&normalizedMantissa = (baseBits & 0x7FFFFF) | 0x3F800000;
        exponentAsFloat = fastCastS16ToFloat(&exponent);
        normalizedMantissa = (lbl_803E7BF4 * exponentValue) * (normalizedMantissa + exponentAsFloat);
        *(u32 *)&result = (u32)(int)normalizedMantissa + 0x3F800000;

        if (baseBits & 0x80000000) {
            integerPower = exponentValue;
            if (integerPower & 1) {
                *(u32 *)&result ^= 0x80000000;
            }
        }

        return result;
    }

    if (exponentValue != lbl_803E7AB8) {
        return lbl_803E7AB8;
    }

    return lbl_803E7BC8;
}
#pragma optimize_for_size reset
#pragma optimization_level reset

#pragma optimization_level 0
#pragma peephole off
void Vec_normalize(void* input, void* output) {
    Vec_scale(input, output, invSqrt(Vec_lengthSquared(input)));
}
#pragma optimization_level reset

#pragma peephole on
void Vec_scale(void* input, void* output, float scale) {
    const Vec* inputVector = input;
    Vec* outputVector = output;
    outputVector->x = inputVector->x * scale;
    outputVector->y = inputVector->y * scale;
    outputVector->z = inputVector->z * scale;
}

float Vec_lengthSquared(void* input) {
    volatile const Vec* vector = input;
    return vector->z * vector->z + (vector->x * vector->x + vector->y * vector->y);
}

#pragma optimization_level 0
#pragma optimize_for_size on
#pragma peephole off
float trigReduceQuadrant(u16* quadrant, float angle) {
    float scaledAngle = lbl_803E7BF8 * __fabsf(angle);
    float roundedQuadrant;
    fastCastFloatToU16(scaledAngle, quadrant);
    *quadrant = (*quadrant + 1) & 0xFFFE;
    roundedQuadrant = fastCastU16ToFloat(quadrant);
    return scaledAngle - roundedQuadrant;
}
#pragma optimize_for_size reset
#pragma optimization_level reset
