#include "dolphin/types.h"
#include "main/math_8029312c.h"
#include "main/trig_float_helpers.h"
#include "main/acosf.h"
#include "main/acosf_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"


float asinf(float value) {
    float absoluteValue = __fabsf(value);
    float reduced;
    float polynomial;
    float root;

    if (absoluteValue <= 0.5f) {
        reduced = value * value;
        return value * (0.19452852f * reduced + 0.9981575f);
    }

    reduced = 0.5f - 0.5f * absoluteValue;
    root = sqrtfHighPrecision(reduced);
    polynomial = root * (0.19452852f * reduced + 0.9981575f);
    if (value >= 0.0f) {
        return 1.5707964f - 2.0f * polynomial;
    }
    return 2.0f * polynomial - 1.5707964f;
}

float acosf_fast(float value) {
    float absoluteValue = __fabsf(value);
    float reduced;
    float polynomial;
    float root;

    if (absoluteValue <= 0.5f) {
        reduced = value * value;
        return 1.5707964f - value * (0.19452852f * reduced + 0.9981575f);
    }

    reduced = 0.5f - 0.5f * absoluteValue;
    root = sqrtfHighPrecision(reduced);
    polynomial = root * (0.19452852f * reduced + 0.9981575f);
    if (value >= 0.0f) {
        return 2.0f * polynomial;
    }
    return 3.1415927f - 2.0f * polynomial;
}

float acosf(float value) {
    float absoluteValue = __fabsf(value);
    float reduced;
    float polynomial;
    float root;

    if (absoluteValue <= 0.5f) {
        reduced = value * value;
        return 1.5707964f - value * (reduced * (reduced * (reduced * (reduced * (0.044916496f * reduced + 0.022284873f) + 0.045945134f)
                                      + 0.074900925f) + 0.16666986f) + 1.0f);
    }

    reduced = 0.5f - 0.5f * absoluteValue;
    root = sqrtfHighPrecision(reduced);
    polynomial = root
        * (reduced * (reduced * (reduced * (reduced * (0.044916496f * reduced + 0.022284873f) + 0.045945134f) + 0.074900925f)
            + 0.16666986f) + 1.0f);
    if (value >= 0.0f) {
        return 2.0f * polynomial;
    }
    return 3.1415927f - 2.0f * polynomial;
}

float atanf_fast(float value) {
    float absoluteValue = __fabsf(value);
    float reciprocal;
    float squared;
    float polynomial;
    float positiveResult;
    float negativeResult;

    if (absoluteValue <= 1.0f) {
        squared = value * value;
        return value * (squared * (0.07803718f * squared + -0.28706065f) + 0.99494934f);
    }

    reciprocal = fastReciprocal(absoluteValue);
    squared = reciprocal * reciprocal;
    polynomial = squared * (0.07803718f * squared + -0.28706065f) + 0.99494934f;
    positiveResult = 1.5707964f - reciprocal * polynomial;
    negativeResult = reciprocal * polynomial - 1.5707964f;
    if (value >= 0.0f) {
        return positiveResult;
    }
    return negativeResult;
}

float atanf(float value) {
    float absoluteValue = __fabsf(value);
    double reduced;
    double squared;
    float result;

    if (absoluteValue <= 1.0f) {
        squared = value * value;
        return (float)(value * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (-0.00009545564651489258 * squared + 0.0008865618705749518) + -0.0038832764327526095)
                                       + 0.010781633704900742) + -0.021653463803231715) + 0.034329998614266506)
                                    + -0.04621516760962549) + 0.05642012785770931) + -0.06598304215265671)
                                 + 0.0767790623192377) + -0.09088734552851294) + 0.11110886338281603)
                              + -0.14285699432451082) + 0.19999999438016125) + -0.3333333332339238)
                           + 0.9999999999994954));
    }

    /* Unsequenced modification and access of `reduced`: undefined behaviour in C.
       MWCC evaluates the assignment first, so retail computes squared = reduced * reduced.
       Required for the byte match -- splitting it into two statements assigns absoluteValue
       and reduced to swapped FPRs (f30/f29) and breaks atanf. Compilers that evaluate the
       left operand first read `reduced` uninitialised and return NaN for every |value| > 1;
       non-MWCC consumers must patch this locally. */
    squared = reduced * (reduced = 1.0 / absoluteValue);
    result = (float)(1.5707963267948966
                     - reduced * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (squared * (-0.00009545564651489258 * squared + 0.0008865618705749518) + -0.0038832764327526095)
                                        + 0.010781633704900742) + -0.021653463803231715) + 0.034329998614266506)
                                     + -0.04621516760962549) + 0.05642012785770931) + -0.06598304215265671)
                                  + 0.0767790623192377) + -0.09088734552851294) + 0.11110886338281603)
                               + -0.14285699432451082) + 0.19999999438016125) + -0.3333333332339238)
                            + 0.9999999999994954));
    if (value >= 0.0f) {
        return result;
    }
    return -result;
}

typedef union FloatWord {
    float value;
    u32 bits;
} FloatWord;

#define ATAN_SIGNS_POS_X_POS_Y 0x00000000
#define ATAN_SIGNS_POS_X_NEG_Y 0x80000000
#define ATAN_SIGNS_NEG_X_POS_Y 0x40000000

static inline u32 float_bits(const float *value) {
    return ((const FloatWord *)value)->bits;
}

float atan2f_fast(float y, float x) {
    float absoluteX = __fabsf(x);
    float absoluteY = __fabsf(y);
    float axisRatio;
    float ratioSquared;
    float firstQuadrantAngle;
    s32 quadrantSigns;

    if (absoluteX > absoluteY) {
        axisRatio = absoluteY / absoluteX;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = axisRatio * (-0.18951416f * ratioSquared + 0.97056276f);
    } else {
        axisRatio = absoluteX / absoluteY;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = 1.5707964f - axisRatio * (-0.18951416f * ratioSquared + 0.97056276f);
    }

    quadrantSigns = (((const FloatWord*)&y)->bits & 0x80000000) |
                    ((((const FloatWord*)&x)->bits & 0x80000000) >> 1);
    switch (quadrantSigns) {
        case ATAN_SIGNS_POS_X_POS_Y:
            return firstQuadrantAngle;
        case ATAN_SIGNS_POS_X_NEG_Y:
            return -firstQuadrantAngle;
        case ATAN_SIGNS_NEG_X_POS_Y:
            return 3.1415927f - firstQuadrantAngle;
        default:
            return firstQuadrantAngle - 3.1415927f;
    }
}

float atan2f(float y, float x) {
    float absoluteX = __fabsf(x);
    float absoluteY = __fabsf(y);
    float axisRatio;
    float ratioSquared;
    float firstQuadrantAngle;
    int quadrantSigns;

    if (absoluteX > absoluteY) {
        axisRatio = absoluteY / absoluteX;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = axisRatio * (ratioSquared * (ratioSquared * (-0.038254466f * ratioSquared + 0.14498249f) + -0.3205333f) + 0.99913347f);
    } else {
        axisRatio = absoluteX / absoluteY;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = 1.5707964f - axisRatio * (ratioSquared * (ratioSquared * (-0.038254466f * ratioSquared + 0.14498249f) + -0.3205333f) + 0.99913347f);
    }

    quadrantSigns = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (quadrantSigns) {
        case ATAN_SIGNS_POS_X_POS_Y:
            return firstQuadrantAngle;
        case ATAN_SIGNS_POS_X_NEG_Y:
            return -firstQuadrantAngle;
        case ATAN_SIGNS_NEG_X_POS_Y:
            return 3.1415927f - firstQuadrantAngle;
        default:
            return firstQuadrantAngle - 3.1415927f;
    }
}

float atan2fHighPrecision(float y, float x) {
    float absoluteX = __fabsf(x);
    float absoluteY = __fabsf(y);
    double axisRatio;
    double ratioSquared;
    double firstQuadrantAngle;
    int quadrantSigns;

    if (absoluteX >= absoluteY) {
        axisRatio = absoluteY / absoluteX;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = axisRatio * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (-0.00009545564651489258 * ratioSquared + 0.0008865618705749518) + -0.0038832764327526095) + 0.010781633704900742)
                       + -0.021653463803231715) + 0.034329998614266506) + -0.04621516760962549) + 0.05642012785770931)
                    + -0.06598304215265671) + 0.0767790623192377) + -0.09088734552851294) + 0.11110886338281603)
                 + -0.14285699432451082) + 0.19999999438016125) + -0.3333333332339238) + 0.9999999999994954);
    } else {
        axisRatio = absoluteX / absoluteY;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = 1.5707963267948966 - axisRatio * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (ratioSquared * (-0.00009545564651489258 * ratioSquared + 0.0008865618705749518) + -0.0038832764327526095) + 0.010781633704900742)
                       + -0.021653463803231715) + 0.034329998614266506) + -0.04621516760962549) + 0.05642012785770931)
                    + -0.06598304215265671) + 0.0767790623192377) + -0.09088734552851294) + 0.11110886338281603)
                 + -0.14285699432451082) + 0.19999999438016125) + -0.3333333332339238) + 0.9999999999994954);
    }

    quadrantSigns = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (quadrantSigns) {
        case ATAN_SIGNS_POS_X_POS_Y:
            return (float)firstQuadrantAngle;
        case ATAN_SIGNS_POS_X_NEG_Y:
            return (float)-firstQuadrantAngle;
        case ATAN_SIGNS_NEG_X_POS_Y:
            return (float)(3.141592653589793 - firstQuadrantAngle);
        default:
            return (float)(firstQuadrantAngle - 3.141592653589793);
    }
}
