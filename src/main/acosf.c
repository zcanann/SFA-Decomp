#include "dolphin/types.h"
#include "main/math_8029312c.h"
#include "main/reciprocal.h"
#include "main/acosf.h"
#include "main/acosf_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

/* Address-based reads retain these named constants without duplicate literals. */
const float sArcHalf = 0.5f;
const float sArcZero = 0.0f;
const float sArcHalfPiF = 1.5707964f;
const float sArcTwo = 2.0f;
const float sArcSinFastCoeff1 = 0.9981575f;
const float sArcSinFastCoeff3 = 0.19452852f;
const float sArcOneF = 1.0f;
const double sArcHalfPiD = 1.5707963267948966;
const float sArcPiF = 3.1415927f;
const float sArcSinCoeff3 = 0.16666986f;
const float sArcSinCoeff5 = 0.074900925f;
const float sArcSinCoeff7 = 0.045945134f;
const float sArcSinCoeff9 = 0.022284873f;
const float sArcSinCoeff11 = 0.044916496f;
const double sArcPiD = 3.141592653589793;
const float sAtan2FastCoeff1 = 0.97056276f;
const float sAtan2FastCoeff3 = -0.18951416f;
const float sAtanFastCoeff1 = 0.99494934f;
const float sAtanFastCoeff3 = -0.28706065f;
const float sAtanFastCoeff5 = 0.07803718f;
const float sAtan2Coeff1 = 0.99913347f;
const float sAtan2Coeff3 = -0.3205333f;
const float sAtan2Coeff5 = 0.14498249f;
const float sAtan2Coeff7 = -0.038254466f;
const double sAtanCoeff1 = 0.9999999999994954;
const double sAtanCoeff3 = -0.3333333332339238;
const double sAtanCoeff5 = 0.19999999438016125;
const double sAtanCoeff7 = -0.14285699432451082;
const double sAtanCoeff9 = 0.11110886338281603;
const double sAtanCoeff11 = -0.09088734552851294;
const double sAtanCoeff13 = 0.0767790623192377;
const double sAtanCoeff15 = -0.06598304215265671;
const double sAtanCoeff17 = 0.05642012785770931;
const double sAtanCoeff19 = -0.04621516760962549;
const double sAtanCoeff21 = 0.034329998614266506;
const double sAtanCoeff23 = -0.021653463803231715;
const double sAtanCoeff25 = 0.010781633704900742;
const double sAtanCoeff27 = -0.0038832764327526095;
const double sAtanCoeff29 = 0.0008865618705749518;
const double sAtanCoeff31 = -0.00009545564651489258;
const double sArcOneD = 1.0;

float asinf(float value) {
    float reduced = __fabsf(value);
    float polynomial;

    if (reduced <= *(const float*)&sArcHalf) {
        reduced = value * value;
        return value * (*(const float*)&sArcSinFastCoeff3 * reduced + *(const float*)&sArcSinFastCoeff1);
    }

    reduced = *(const float*)&sArcHalf - *(const float*)&sArcHalf * reduced;
    polynomial = sqrtfHighPrecision(reduced);
    polynomial = polynomial * (*(const float*)&sArcSinFastCoeff3 * reduced + *(const float*)&sArcSinFastCoeff1);
    if (value >= *(const float*)&sArcZero) {
        return *(const float*)&sArcHalfPiF - *(const float*)&sArcTwo * polynomial;
    }
    return *(const float*)&sArcTwo * polynomial - *(const float*)&sArcHalfPiF;
}

float acosf_fast(float value) {
    float reduced = __fabsf(value);
    float polynomial;

    if (reduced <= *(const float*)&sArcHalf) {
        reduced = value * value;
        return *(const float*)&sArcHalfPiF -
               value * (*(const float*)&sArcSinFastCoeff3 * reduced + *(const float*)&sArcSinFastCoeff1);
    }

    reduced = *(const float*)&sArcHalf - *(const float*)&sArcHalf * reduced;
    polynomial = sqrtfHighPrecision(reduced);
    polynomial = polynomial * (*(const float*)&sArcSinFastCoeff3 * reduced + *(const float*)&sArcSinFastCoeff1);
    if (value >= *(const float*)&sArcZero) {
        return *(const float*)&sArcTwo * polynomial;
    }
    return *(const float*)&sArcPiF - *(const float*)&sArcTwo * polynomial;
}

float acosf(float value) {
    float reduced = __fabsf(value);
    float polynomial;

    if (reduced <= *(const float*)&sArcHalf) {
        reduced = value * value;
        return *(const float*)&sArcHalfPiF -
               value * (reduced * (reduced * (reduced * (reduced * (*(const float*)&sArcSinCoeff11 * reduced +
                                                                    *(const float*)&sArcSinCoeff9) +
                                                         *(const float*)&sArcSinCoeff7) +
                                              *(const float*)&sArcSinCoeff5) +
                                   *(const float*)&sArcSinCoeff3) +
                        *(const float*)&sArcOneF);
    }

    reduced = *(const float*)&sArcHalf - *(const float*)&sArcHalf * reduced;
    polynomial = sqrtfHighPrecision(reduced);
    polynomial = polynomial * (reduced * (reduced * (reduced * (reduced * (*(const float*)&sArcSinCoeff11 * reduced +
                                                                     *(const float*)&sArcSinCoeff9) +
                                                          *(const float*)&sArcSinCoeff7) +
                                               *(const float*)&sArcSinCoeff5) +
                                    *(const float*)&sArcSinCoeff3) +
                         *(const float*)&sArcOneF);
    if (value >= *(const float*)&sArcZero) {
        return *(const float*)&sArcTwo * polynomial;
    }
    return *(const float*)&sArcPiF - *(const float*)&sArcTwo * polynomial;
}

float atanf_fast(float value) {
    float reduced = __fabsf(value);
    float polynomial;
    float positiveResult;
    float negativeResult;

    if (reduced <= *(const float*)&sArcOneF) {
        polynomial = value * value;
        return value * (polynomial * (*(const float*)&sAtanFastCoeff5 * polynomial + *(const float*)&sAtanFastCoeff3) +
                        *(const float*)&sAtanFastCoeff1);
    }

    reduced = fastReciprocal(reduced);
    polynomial = reduced * reduced;
    polynomial = polynomial * (*(const float*)&sAtanFastCoeff5 * polynomial + *(const float*)&sAtanFastCoeff3) +
                 *(const float*)&sAtanFastCoeff1;
    positiveResult = *(const float*)&sArcHalfPiF - reduced * polynomial;
    negativeResult = reduced * polynomial - *(const float*)&sArcHalfPiF;
    if (value >= *(const float*)&sArcZero) {
        return positiveResult;
    }
    return negativeResult;
}

float atanf(float value) {
    double reduced = __fabsf(value);
    double squared;
    float result;

    if (reduced <= *(const float*)&sArcOneF) {
        squared = value * value;
        return (
            float)(value *
                   (squared *
                        (squared *
                             (squared *
                                  (squared *
                                       (squared *
                                            (squared *
                                                 (squared *
                                                      (squared *
                                                           (squared *
                                                                (squared *
                                                                     (squared *
                                                                          (squared *
                                                                               (squared *
                                                                                    (squared *
                                                                                         (*(const double*)&sAtanCoeff31 *
                                                                                              squared +
                                                                                          *(const double*)&sAtanCoeff29) +
                                                                                     *(const double*)&sAtanCoeff27) +
                                                                                *(const double*)&sAtanCoeff25) +
                                                                           *(const double*)&sAtanCoeff23) +
                                                                      *(const double*)&sAtanCoeff21) +
                                                                 *(const double*)&sAtanCoeff19) +
                                                            *(const double*)&sAtanCoeff17) +
                                                       *(const double*)&sAtanCoeff15) +
                                                  *(const double*)&sAtanCoeff13) +
                                             *(const double*)&sAtanCoeff11) +
                                        *(const double*)&sAtanCoeff9) +
                                   *(const double*)&sAtanCoeff7) +
                              *(const double*)&sAtanCoeff5) +
                         *(const double*)&sAtanCoeff3) +
                    *(const double*)&sAtanCoeff1));
    }

    reduced = *(const double*)&sArcOneD / reduced;
    squared = reduced * reduced;
    result =
        (float)(*(const double*)&sArcHalfPiD -
                reduced *
                    (squared *
                         (squared *
                              (squared *
                                   (squared *
                                        (squared *
                                             (squared *
                                                  (squared *
                                                       (squared *
                                                            (squared *
                                                                 (squared *
                                                                      (squared *
                                                                           (squared *
                                                                                (squared *
                                                                                     (squared *
                                                                                          (*(const double*)&sAtanCoeff31 *
                                                                                               squared +
                                                                                           *(const double*)&sAtanCoeff29) +
                                                                                      *(const double*)&sAtanCoeff27) +
                                                                                 *(const double*)&sAtanCoeff25) +
                                                                            *(const double*)&sAtanCoeff23) +
                                                                       *(const double*)&sAtanCoeff21) +
                                                                  *(const double*)&sAtanCoeff19) +
                                                             *(const double*)&sAtanCoeff17) +
                                                        *(const double*)&sAtanCoeff15) +
                                                   *(const double*)&sAtanCoeff13) +
                                              *(const double*)&sAtanCoeff11) +
                                         *(const double*)&sAtanCoeff9) +
                                    *(const double*)&sAtanCoeff7) +
                               *(const double*)&sAtanCoeff5) +
                          *(const double*)&sAtanCoeff3) +
                     *(const double*)&sAtanCoeff1));
    if (value >= *(const float*)&sArcZero) {
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

static inline u32 float_bits(const float* value) {
    return ((const FloatWord*)value)->bits;
}

float atan2f_fast(float y, float x) {
    float absoluteX = __fabsf(x);
    float absoluteY = __fabsf(y);
    float angle;
    float ratioSquared;
    s32 quadrantSigns;

    if (absoluteX > absoluteY) {
        angle = absoluteY / absoluteX;
        ratioSquared = angle * angle;
        angle =
            angle * (*(const float*)&sAtan2FastCoeff3 * ratioSquared + *(const float*)&sAtan2FastCoeff1);
    } else {
        angle = absoluteX / absoluteY;
        ratioSquared = angle * angle;
        angle =
            *(const float*)&sArcHalfPiF -
            angle * (*(const float*)&sAtan2FastCoeff3 * ratioSquared + *(const float*)&sAtan2FastCoeff1);
    }

    quadrantSigns = (((const FloatWord*)&y)->bits & 0x80000000) | ((((const FloatWord*)&x)->bits & 0x80000000) >> 1);
    switch (quadrantSigns) {
    case ATAN_SIGNS_POS_X_POS_Y:
        return angle;
    case ATAN_SIGNS_POS_X_NEG_Y:
        return -angle;
    case ATAN_SIGNS_NEG_X_POS_Y:
        return *(const float*)&sArcPiF - angle;
    default:
        return angle - *(const float*)&sArcPiF;
    }
}

float atan2f(float y, float x) {
    float absoluteX = __fabsf(x);
    float absoluteY = __fabsf(y);
    float angle;
    float ratioSquared;
    int quadrantSigns;

    if (absoluteX > absoluteY) {
        angle = absoluteY / absoluteX;
        ratioSquared = angle * angle;
        angle = angle * (ratioSquared * (ratioSquared * (*(const float*)&sAtan2Coeff7 * ratioSquared +
                                                                          *(const float*)&sAtan2Coeff5) +
                                                          *(const float*)&sAtan2Coeff3) +
                                          *(const float*)&sAtan2Coeff1);
    } else {
        angle = absoluteX / absoluteY;
        ratioSquared = angle * angle;
        angle = *(const float*)&sArcHalfPiF -
                             angle * (ratioSquared * (ratioSquared * (*(const float*)&sAtan2Coeff7 * ratioSquared +
                                                                          *(const float*)&sAtan2Coeff5) +
                                                          *(const float*)&sAtan2Coeff3) +
                                          *(const float*)&sAtan2Coeff1);
    }

    quadrantSigns = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (quadrantSigns) {
    case ATAN_SIGNS_POS_X_POS_Y:
        return angle;
    case ATAN_SIGNS_POS_X_NEG_Y:
        return -angle;
    case ATAN_SIGNS_NEG_X_POS_Y:
        return *(const float*)&sArcPiF - angle;
    default:
        return angle - *(const float*)&sArcPiF;
    }
}

float atan2fHighPrecision(float y, float x) {
    float absoluteX = __fabsf(x);
    float absoluteY = __fabsf(y);
    double angle;
    double ratioSquared;
    int quadrantSigns;

    if (absoluteX >= absoluteY) {
        angle = absoluteY / absoluteX;
        ratioSquared = angle * angle;
        angle =
            angle *
            (ratioSquared *
                 (ratioSquared *
                      (ratioSquared *
                           (ratioSquared *
                                (ratioSquared *
                                     (ratioSquared *
                                          (ratioSquared *
                                               (ratioSquared *
                                                    (ratioSquared *
                                                         (ratioSquared *
                                                              (ratioSquared *
                                                                   (ratioSquared *
                                                                        (ratioSquared *
                                                                             (ratioSquared *
                                                                                  (*(const double*)&sAtanCoeff31 *
                                                                                       ratioSquared +
                                                                                   *(const double*)&sAtanCoeff29) +
                                                                              *(const double*)&sAtanCoeff27) +
                                                                         *(const double*)&sAtanCoeff25) +
                                                                    *(const double*)&sAtanCoeff23) +
                                                               *(const double*)&sAtanCoeff21) +
                                                          *(const double*)&sAtanCoeff19) +
                                                     *(const double*)&sAtanCoeff17) +
                                                *(const double*)&sAtanCoeff15) +
                                           *(const double*)&sAtanCoeff13) +
                                      *(const double*)&sAtanCoeff11) +
                                 *(const double*)&sAtanCoeff9) +
                            *(const double*)&sAtanCoeff7) +
                       *(const double*)&sAtanCoeff5) +
                  *(const double*)&sAtanCoeff3) +
             *(const double*)&sAtanCoeff1);
    } else {
        angle = absoluteX / absoluteY;
        ratioSquared = angle * angle;
        angle =
            *(const double*)&sArcHalfPiD -
            angle *
                (ratioSquared *
                     (ratioSquared *
                          (ratioSquared *
                               (ratioSquared *
                                    (ratioSquared *
                                         (ratioSquared *
                                              (ratioSquared *
                                                   (ratioSquared *
                                                        (ratioSquared *
                                                             (ratioSquared *
                                                                  (ratioSquared *
                                                                       (ratioSquared *
                                                                            (ratioSquared *
                                                                                 (ratioSquared *
                                                                                      (*(const double*)&sAtanCoeff31 *
                                                                                           ratioSquared +
                                                                                       *(const double*)&sAtanCoeff29) +
                                                                                  *(const double*)&sAtanCoeff27) +
                                                                             *(const double*)&sAtanCoeff25) +
                                                                        *(const double*)&sAtanCoeff23) +
                                                                   *(const double*)&sAtanCoeff21) +
                                                              *(const double*)&sAtanCoeff19) +
                                                         *(const double*)&sAtanCoeff17) +
                                                    *(const double*)&sAtanCoeff15) +
                                               *(const double*)&sAtanCoeff13) +
                                          *(const double*)&sAtanCoeff11) +
                                     *(const double*)&sAtanCoeff9) +
                                *(const double*)&sAtanCoeff7) +
                           *(const double*)&sAtanCoeff5) +
                      *(const double*)&sAtanCoeff3) +
                 *(const double*)&sAtanCoeff1);
    }

    quadrantSigns = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (quadrantSigns) {
    case ATAN_SIGNS_POS_X_POS_Y:
        return (float)angle;
    case ATAN_SIGNS_POS_X_NEG_Y:
        return (float)-angle;
    case ATAN_SIGNS_NEG_X_POS_Y:
        return (float)(*(const double*)&sArcPiD - angle);
    default:
        return (float)(angle - *(const double*)&sArcPiD);
    }
}
