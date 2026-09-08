#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

/* Address-based reads retain these named constants without duplicate literals. */
const float sTanNegativeOne = -1.0f;
const float sTanZero = 0.0f;
const float sTanReducedCoeff1 = 0.785224974155426f;
const float sTanReducedCoeff3 = 0.16370797157287598f;
const float sTanReducedCoeff5 = 0.03238091617822647f;
const float sTanReducedCoeff7 = 0.018663575872778893f;

float mathTanf(float angle) {
    u16 evenOctant;
    float quarterPiRemainder = trigReduceQuadrant(&evenOctant, angle);
    float remainderSquared = quarterPiRemainder * quarterPiRemainder;
    float tangent = quarterPiRemainder *
                    (((*(const float*)&sTanReducedCoeff7 * remainderSquared + *(const float*)&sTanReducedCoeff5) *
                          remainderSquared +
                      *(const float*)&sTanReducedCoeff3) *
                         remainderSquared +
                     *(const float*)&sTanReducedCoeff1);

    if (evenOctant & 2) {
        tangent = *(const float*)&sTanNegativeOne / tangent;
    }

    if (angle >= *(const float*)&sTanZero) {
        return tangent;
    }
    return -tangent;
}

typedef union MathFloatBits {
    float value;
    u32 bits;
} MathFloatBits;

float log2fBitEstimate(float value) {
    MathFloatBits normalizedMantissa;
    u32 rawBits;
    float exponentAsFloat;
    s16 exponent;

    rawBits = ((const MathFloatBits*)&value)->bits;
    /* The normalized mantissa contributes one, so subtract bias + 1. */
    exponent = (s16)(((rawBits >> 23) & 0xFF) - 128);
    normalizedMantissa.bits = (rawBits & 0x7FFFFF) | 0x3F800000;

    exponentAsFloat = fastCastS16ToFloat(&exponent);
    return normalizedMantissa.value + exponentAsFloat;
}
