#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/math_8029312c.h"

float powfCoreHighPrecision(float base, float power) {
    register double logValue;
    register u32 baseBits;
    register int baseExponent;
    register int resultExponent;
    register int integerPower;
    union {
        float value;
        u32 bits;
    } result;
    union {
        float value;
        u32 bits;
    } normalizedBase;

    if (base) {
        baseBits = *(u32*)&base;
        baseExponent = (s16)(((baseBits >> 23) & 0xFF) - 127);
        normalizedBase.bits = (baseBits & 0x7FFFFF) | 0x3F800000;
        logValue = normalizedBase.value - 1.0;
        logValue =
            logValue *
            (logValue *
                 (logValue *
                      (logValue *
                           (logValue *
                                (logValue *
                                     (logValue *
                                          (logValue *
                                               (logValue *
                                                    (logValue *
                                                         (logValue *
                                                              (logValue *
                                                                   (logValue *
                                                                        (logValue *
                                                                             (logValue *
                                                                                  (logValue *
                                                                                       (logValue *
                                                                                            (logValue *
                                                                                                 (logValue *
                                                                                                      (-8.069157600402832e-05 *
                                                                                                           logValue +
                                                                                                       0.0008901345729827878) +
                                                                                                  -0.004606819599866867) +
                                                                                             0.014949040506035093) +
                                                                                        -0.034416124052368116) +
                                                                                   0.06065611486672425) +
                                                                              -0.0869755039268057) +
                                                                         0.10761304204199404) +
                                                                    -0.12190974608105533) +
                                                               0.13324794327085782) +
                                                          -0.1454174778986362) +
                                                     0.1607154142236368) +
                                                -0.18044406414683764) +
                                           0.2061192119261031) +
                                      -0.24045182041398597) +
                                 0.28853925385776685) +
                            -0.3606737755753234) +
                       0.480898347574289) +
                  -0.7213475204586257) +
             1.4426950408891204);
        /* Convert the base logarithm to the result exponent. */
        logValue = power * (logValue + (double)baseExponent);
        resultExponent = logValue;
        /* Retain the fractional part for the exp2 polynomial. */
        logValue = logValue - (double)resultExponent;

        if (logValue) {
            result.value =
                (float)(logValue *
                            (logValue *
                                 (logValue *
                                      (logValue *
                                           (logValue *
                                                (logValue *
                                                     (logValue *
                                                          (logValue * (logValue * (9.926346441109975e-09 * logValue +
                                                                                   9.472326685984924e-08) +
                                                                       1.3310673239175234e-06) +
                                                           1.5244851723158107e-05) +
                                                      0.00015403947598618592) +
                                                 0.0013333543997684197) +
                                            0.00961812940579326) +
                                       0.055504108628658844) +
                                  0.24022650696122427) +
                             0.693147180559909) +
                        0.9999999999999999);
        } else {
            result.value = 1.0f;
        }

        if ((int)(baseBits & 0x80000000)) {
            integerPower = power;
            if (integerPower & 1) {
                result.value = -result.value;
            }
        }
        /* Apply the signed exponent through binary32 word arithmetic. */
        result.bits += (u32)resultExponent << 23;
        return result.value;
    }
    if (power) {
        return 0.0f;
    }
    return 1.0f;
}

float powfCoreFast(float base, register float power) {
    register u32 baseBits;
    register int integerPower;
    union {
        float value;
        u32 bits;
    } result;
    union {
        float value;
        u32 bits;
    } logValue;
    s16 baseExponent;
    s16 resultExponent;

    if (base) {
        baseBits = *(u32*)&base;
        baseExponent = ((baseBits >> 23) & 0xFF) - 127;
        logValue.bits = (baseBits & 0x7FFFFF) | 0x3F800000;
        logValue.value = logValue.value - 1.0f;
        logValue.value = logValue.value * (logValue.value * (0.15544586f * logValue.value + -0.5729206f) + 1.4172995f) +
                         0.00072527403f;
        logValue.value = power * (logValue.value + fastCastS16ToFloat(&baseExponent));
        fastCastFloatToS16(logValue.value, &resultExponent);
        logValue.value = logValue.value - fastCastS16ToFloat(&resultExponent);
        if (logValue.value) {
            result.value = (logValue.value * (0.3431449f * logValue.value + 0.6519048f) + 1.0023681f);
        } else {
            result.value = 1.0f;
        }
        if ((int)(baseBits & 0x80000000)) {
            integerPower = power;
            if (integerPower & 1) {
                result.value = -result.value;
            }
        }
        /* Apply the signed exponent through binary32 word arithmetic. */
        result.bits += (u32)resultExponent << 23;
        return result.value;
    }
    if (power) {
        return 0.0f;
    }
    return 1.0f;
}

#pragma optimization_level 0
#pragma optimize_for_size on
float powfBitEstimate(float base, float exponentValue) {
    u32 baseBits;
    union {
        float value;
        u32 bits;
    } result;
    union {
        float value;
        u32 bits;
    } normalizedMantissa;
    s16 exponent;
    float exponentAsFloat;
    int integerPower;

    if (base) {
        baseBits = *(u32*)&base;
        exponent = (s16)(((baseBits >> 23) & 0xFF) - 128);
        normalizedMantissa.bits = (baseBits & 0x7FFFFF) | 0x3F800000;
        exponentAsFloat = fastCastS16ToFloat(&exponent);
        normalizedMantissa.value = (8388608.0f * exponentValue) * (normalizedMantissa.value + exponentAsFloat);
        result.bits = (u32)(int)normalizedMantissa.value + 0x3F800000;

        if (baseBits & 0x80000000) {
            integerPower = exponentValue;
            if (integerPower & 1) {
                result.bits ^= 0x80000000;
            }
        }

        return result.value;
    }

    if (exponentValue) {
        return 0.0f;
    }

    return 1.0f;
}
#pragma optimize_for_size reset
#pragma optimization_level reset

#pragma optimization_level 0
#pragma peephole off
void Vec_normalize(const Vec* input, Vec* output) {
    Vec_scale(input, output, invSqrt(Vec_lengthSquared(input)));
}
#pragma optimization_level reset

#pragma peephole on
void Vec_scale(const Vec* input, Vec* output, float scale) {
    output->x = input->x * scale;
    output->y = input->y * scale;
    output->z = input->z * scale;
}

float Vec_lengthSquared(const Vec* input) {
    return input->z * input->z + (input->x * input->x + input->y * input->y);
}

#pragma optimization_level 0
#pragma optimize_for_size on
#pragma peephole off
float trigReduceQuadrant(u16* quadrant, float angle) {
    float scaledAngle = 1.2732395f * __fabsf(angle);
    fastCastFloatToU16(scaledAngle, quadrant);
    *quadrant = (*quadrant + 1) & 0xFFFE;
    return scaledAngle - fastCastU16ToFloat(quadrant);
}
#pragma optimize_for_size reset
#pragma optimization_level reset
