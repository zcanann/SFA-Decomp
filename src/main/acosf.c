#include "dolphin/types.h"
#include "main/math_8029312c.h"
#include "main/trig_float_helpers.h"
#include "main/acosf.h"
#include "main/acosf_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

extern const float sArcHalf;
extern const float sArcZero;
extern const float sArcHalfPiF;
extern const float sArcTwo;
extern const float sArcSinFastCoeff1;
extern const float sArcSinFastCoeff3;
extern const float sArcOneF;
extern const double sArcHalfPiD;
extern const float sArcPiF;
extern const float sArcSinCoeff3;
extern const float sArcSinCoeff5;
extern const float sArcSinCoeff7;
extern const float sArcSinCoeff9;
extern const float sArcSinCoeff11;
extern const double sArcPiD;
extern const float sAtan2FastCoeff1;
extern const float sAtan2FastCoeff3;
extern const float sAtanFastCoeff1;
extern const float sAtanFastCoeff3;
extern const float sAtanFastCoeff5;
extern const float sAtan2Coeff1;
extern const float sAtan2Coeff3;
extern const float sAtan2Coeff5;
extern const float sAtan2Coeff7;
extern const double sAtanCoeff1;
extern const double sAtanCoeff3;
extern const double sAtanCoeff5;
extern const double sAtanCoeff7;
extern const double sAtanCoeff9;
extern const double sAtanCoeff11;
extern const double sAtanCoeff13;
extern const double sAtanCoeff15;
extern const double sAtanCoeff17;
extern const double sAtanCoeff19;
extern const double sAtanCoeff21;
extern const double sAtanCoeff23;
extern const double sAtanCoeff25;
extern const double sAtanCoeff27;
extern const double sAtanCoeff29;
extern const double sAtanCoeff31;
extern const double sArcOneD;

float asinf(float value) {
    float absoluteValue = __fabsf(value);
    float reduced;
    float polynomial;
    float root;

    if (absoluteValue <= sArcHalf) {
        reduced = value * value;
        return value * (sArcSinFastCoeff3 * reduced + sArcSinFastCoeff1);
    }

    reduced = sArcHalf - sArcHalf * absoluteValue;
    root = sqrtfHighPrecision(reduced);
    polynomial = root * (sArcSinFastCoeff3 * reduced + sArcSinFastCoeff1);
    if (value >= sArcZero) {
        return sArcHalfPiF - sArcTwo * polynomial;
    }
    return sArcTwo * polynomial - sArcHalfPiF;
}

float acosf_fast(float value) {
    float absoluteValue = __fabsf(value);
    float reduced;
    float polynomial;
    float root;

    if (absoluteValue <= sArcHalf) {
        reduced = value * value;
        return sArcHalfPiF - value * (sArcSinFastCoeff3 * reduced + sArcSinFastCoeff1);
    }

    reduced = sArcHalf - sArcHalf * absoluteValue;
    root = sqrtfHighPrecision(reduced);
    polynomial = root * (sArcSinFastCoeff3 * reduced + sArcSinFastCoeff1);
    if (value >= sArcZero) {
        return sArcTwo * polynomial;
    }
    return sArcPiF - sArcTwo * polynomial;
}

float acosf(float value) {
    float absoluteValue = __fabsf(value);
    float reduced;
    float polynomial;
    float root;

    if (absoluteValue <= sArcHalf) {
        reduced = value * value;
        return sArcHalfPiF -
               value *
                   (reduced *
                        (reduced * (reduced * (reduced * (sArcSinCoeff11 * reduced + sArcSinCoeff9) + sArcSinCoeff7) +
                                    sArcSinCoeff5) +
                         sArcSinCoeff3) +
                    sArcOneF);
    }

    reduced = sArcHalf - sArcHalf * absoluteValue;
    root = sqrtfHighPrecision(reduced);
    polynomial =
        root * (reduced * (reduced * (reduced * (reduced * (sArcSinCoeff11 * reduced + sArcSinCoeff9) + sArcSinCoeff7) +
                                      sArcSinCoeff5) +
                           sArcSinCoeff3) +
                sArcOneF);
    if (value >= sArcZero) {
        return sArcTwo * polynomial;
    }
    return sArcPiF - sArcTwo * polynomial;
}

float atanf_fast(float value) {
    float absoluteValue = __fabsf(value);
    float reciprocal;
    float squared;
    float polynomial;
    float positiveResult;
    float negativeResult;

    if (absoluteValue <= sArcOneF) {
        squared = value * value;
        return value * (squared * (sAtanFastCoeff5 * squared + sAtanFastCoeff3) + sAtanFastCoeff1);
    }

    reciprocal = fastReciprocal(absoluteValue);
    squared = reciprocal * reciprocal;
    polynomial = squared * (sAtanFastCoeff5 * squared + sAtanFastCoeff3) + sAtanFastCoeff1;
    positiveResult = sArcHalfPiF - reciprocal * polynomial;
    negativeResult = reciprocal * polynomial - sArcHalfPiF;
    if (value >= sArcZero) {
        return positiveResult;
    }
    return negativeResult;
}

float atanf(float value) {
    double reduced = __fabsf(value);
    double squared;
    float result;

    if (reduced <= sArcOneF) {
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
                                                                                    (squared * (sAtanCoeff31 * squared +
                                                                                                sAtanCoeff29) +
                                                                                     sAtanCoeff27) +
                                                                                sAtanCoeff25) +
                                                                           sAtanCoeff23) +
                                                                      sAtanCoeff21) +
                                                                 sAtanCoeff19) +
                                                            sAtanCoeff17) +
                                                       sAtanCoeff15) +
                                                  sAtanCoeff13) +
                                             sAtanCoeff11) +
                                        sAtanCoeff9) +
                                   sAtanCoeff7) +
                              sAtanCoeff5) +
                         sAtanCoeff3) +
                    sAtanCoeff1));
    }

    reduced = sArcOneD / reduced;
    squared = reduced * reduced;
    result =
        (float)(sArcHalfPiD -
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
                                                                                (squared * (squared * (sAtanCoeff31 *
                                                                                                           squared +
                                                                                                       sAtanCoeff29) +
                                                                                            sAtanCoeff27) +
                                                                                 sAtanCoeff25) +
                                                                            sAtanCoeff23) +
                                                                       sAtanCoeff21) +
                                                                  sAtanCoeff19) +
                                                             sAtanCoeff17) +
                                                        sAtanCoeff15) +
                                                   sAtanCoeff13) +
                                              sAtanCoeff11) +
                                         sAtanCoeff9) +
                                    sAtanCoeff7) +
                               sAtanCoeff5) +
                          sAtanCoeff3) +
                     sAtanCoeff1));
    if (value >= sArcZero) {
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
    float axisRatio;
    float ratioSquared;
    float firstQuadrantAngle;
    s32 quadrantSigns;

    if (absoluteX > absoluteY) {
        axisRatio = absoluteY / absoluteX;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = axisRatio * (sAtan2FastCoeff3 * ratioSquared + sAtan2FastCoeff1);
    } else {
        axisRatio = absoluteX / absoluteY;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = sArcHalfPiF - axisRatio * (sAtan2FastCoeff3 * ratioSquared + sAtan2FastCoeff1);
    }

    quadrantSigns = (((const FloatWord*)&y)->bits & 0x80000000) | ((((const FloatWord*)&x)->bits & 0x80000000) >> 1);
    switch (quadrantSigns) {
    case ATAN_SIGNS_POS_X_POS_Y:
        return firstQuadrantAngle;
    case ATAN_SIGNS_POS_X_NEG_Y:
        return -firstQuadrantAngle;
    case ATAN_SIGNS_NEG_X_POS_Y:
        return sArcPiF - firstQuadrantAngle;
    default:
        return firstQuadrantAngle - sArcPiF;
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
        firstQuadrantAngle =
            axisRatio * (ratioSquared * (ratioSquared * (sAtan2Coeff7 * ratioSquared + sAtan2Coeff5) + sAtan2Coeff3) +
                         sAtan2Coeff1);
    } else {
        axisRatio = absoluteX / absoluteY;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle =
            sArcHalfPiF -
            axisRatio * (ratioSquared * (ratioSquared * (sAtan2Coeff7 * ratioSquared + sAtan2Coeff5) + sAtan2Coeff3) +
                         sAtan2Coeff1);
    }

    quadrantSigns = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (quadrantSigns) {
    case ATAN_SIGNS_POS_X_POS_Y:
        return firstQuadrantAngle;
    case ATAN_SIGNS_POS_X_NEG_Y:
        return -firstQuadrantAngle;
    case ATAN_SIGNS_NEG_X_POS_Y:
        return sArcPiF - firstQuadrantAngle;
    default:
        return firstQuadrantAngle - sArcPiF;
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
        firstQuadrantAngle =
            axisRatio *
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
                                                                                  (sAtanCoeff31 * ratioSquared +
                                                                                   sAtanCoeff29) +
                                                                              sAtanCoeff27) +
                                                                         sAtanCoeff25) +
                                                                    sAtanCoeff23) +
                                                               sAtanCoeff21) +
                                                          sAtanCoeff19) +
                                                     sAtanCoeff17) +
                                                sAtanCoeff15) +
                                           sAtanCoeff13) +
                                      sAtanCoeff11) +
                                 sAtanCoeff9) +
                            sAtanCoeff7) +
                       sAtanCoeff5) +
                  sAtanCoeff3) +
             sAtanCoeff1);
    } else {
        axisRatio = absoluteX / absoluteY;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle =
            sArcHalfPiD -
            axisRatio *
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
                                                                                      (sAtanCoeff31 * ratioSquared +
                                                                                       sAtanCoeff29) +
                                                                                  sAtanCoeff27) +
                                                                             sAtanCoeff25) +
                                                                        sAtanCoeff23) +
                                                                   sAtanCoeff21) +
                                                              sAtanCoeff19) +
                                                         sAtanCoeff17) +
                                                    sAtanCoeff15) +
                                               sAtanCoeff13) +
                                          sAtanCoeff11) +
                                     sAtanCoeff9) +
                                sAtanCoeff7) +
                           sAtanCoeff5) +
                      sAtanCoeff3) +
                 sAtanCoeff1);
    }

    quadrantSigns = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (quadrantSigns) {
    case ATAN_SIGNS_POS_X_POS_Y:
        return (float)firstQuadrantAngle;
    case ATAN_SIGNS_POS_X_NEG_Y:
        return (float)-firstQuadrantAngle;
    case ATAN_SIGNS_NEG_X_POS_Y:
        return (float)(sArcPiD - firstQuadrantAngle);
    default:
        return (float)(firstQuadrantAngle - sArcPiD);
    }
}

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
