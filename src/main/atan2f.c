#include "dolphin/types.h"
#include "main/atan2f.h"

extern float lbl_803E79C8;
extern float lbl_803E79E8;
extern double lbl_803E79E0;
extern double lbl_803E7A00;
extern float lbl_803E7A08;
extern float lbl_803E7A0C;
extern float lbl_803E7A1C;
extern float lbl_803E7A20;
extern float lbl_803E7A24;
extern float lbl_803E7A28;
extern double lbl_803E7A30;
extern double lbl_803E7A38;
extern double lbl_803E7A40;
extern double lbl_803E7A48;
extern double lbl_803E7A50;
extern double lbl_803E7A58;
extern double lbl_803E7A60;
extern double lbl_803E7A68;
extern double lbl_803E7A70;
extern double lbl_803E7A78;
extern double lbl_803E7A80;
extern double lbl_803E7A88;
extern double lbl_803E7A90;
extern double lbl_803E7A98;
extern double lbl_803E7AA0;
extern double lbl_803E7AA8;

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

float __kernel_cos(float y, float x) {
    float absoluteX = __fabsf(x);
    float absoluteY = __fabsf(y);
    float axisRatio;
    float ratioSquared;
    float firstQuadrantAngle;
    s32 quadrantSigns;

    if (absoluteX > absoluteY) {
        axisRatio = absoluteY / absoluteX;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = axisRatio * (lbl_803E7A0C * ratioSquared + lbl_803E7A08);
    } else {
        axisRatio = absoluteX / absoluteY;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = lbl_803E79C8 - axisRatio * (lbl_803E7A0C * ratioSquared + lbl_803E7A08);
    }

    quadrantSigns = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (quadrantSigns) {
        case ATAN_SIGNS_POS_X_POS_Y:
            return firstQuadrantAngle;
        case ATAN_SIGNS_POS_X_NEG_Y:
            return -firstQuadrantAngle;
        case ATAN_SIGNS_NEG_X_POS_Y:
            return lbl_803E79E8 - firstQuadrantAngle;
        default:
            return firstQuadrantAngle - lbl_803E79E8;
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
        firstQuadrantAngle = axisRatio * (((lbl_803E7A28 * ratioSquared + lbl_803E7A24) * ratioSquared + lbl_803E7A20) * ratioSquared + lbl_803E7A1C);
    } else {
        axisRatio = absoluteX / absoluteY;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = lbl_803E79C8 - axisRatio * (((lbl_803E7A28 * ratioSquared + lbl_803E7A24) * ratioSquared + lbl_803E7A20) * ratioSquared + lbl_803E7A1C);
    }

    quadrantSigns = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (quadrantSigns) {
        case ATAN_SIGNS_POS_X_POS_Y:
            return firstQuadrantAngle;
        case ATAN_SIGNS_POS_X_NEG_Y:
            return -firstQuadrantAngle;
        case ATAN_SIGNS_NEG_X_POS_Y:
            return lbl_803E79E8 - firstQuadrantAngle;
        default:
            return firstQuadrantAngle - lbl_803E79E8;
    }
}

float fn_802925C4(float y, float x) {
    float absoluteX = __fabsf(x);
    float absoluteY = __fabsf(y);
    double axisRatio;
    double ratioSquared;
    double firstQuadrantAngle;
    int quadrantSigns;

    if (absoluteX >= absoluteY) {
        axisRatio = absoluteY / absoluteX;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = axisRatio * (((((((((((((((lbl_803E7AA8 * ratioSquared + lbl_803E7AA0) * ratioSquared + lbl_803E7A98) * ratioSquared + lbl_803E7A90) * ratioSquared
                       + lbl_803E7A88) * ratioSquared + lbl_803E7A80) * ratioSquared + lbl_803E7A78) * ratioSquared + lbl_803E7A70) * ratioSquared
                    + lbl_803E7A68) * ratioSquared + lbl_803E7A60) * ratioSquared + lbl_803E7A58) * ratioSquared + lbl_803E7A50) * ratioSquared
                 + lbl_803E7A48) * ratioSquared + lbl_803E7A40) * ratioSquared + lbl_803E7A38) * ratioSquared + lbl_803E7A30);
    } else {
        axisRatio = absoluteX / absoluteY;
        ratioSquared = axisRatio * axisRatio;
        firstQuadrantAngle = lbl_803E79E0 - axisRatio * (((((((((((((((lbl_803E7AA8 * ratioSquared + lbl_803E7AA0) * ratioSquared + lbl_803E7A98) * ratioSquared + lbl_803E7A90) * ratioSquared
                       + lbl_803E7A88) * ratioSquared + lbl_803E7A80) * ratioSquared + lbl_803E7A78) * ratioSquared + lbl_803E7A70) * ratioSquared
                    + lbl_803E7A68) * ratioSquared + lbl_803E7A60) * ratioSquared + lbl_803E7A58) * ratioSquared + lbl_803E7A50) * ratioSquared
                 + lbl_803E7A48) * ratioSquared + lbl_803E7A40) * ratioSquared + lbl_803E7A38) * ratioSquared + lbl_803E7A30);
    }

    quadrantSigns = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (quadrantSigns) {
        case ATAN_SIGNS_POS_X_POS_Y:
            return (float)firstQuadrantAngle;
        case ATAN_SIGNS_POS_X_NEG_Y:
            return (float)-firstQuadrantAngle;
        case ATAN_SIGNS_NEG_X_POS_Y:
            return (float)(lbl_803E7A00 - firstQuadrantAngle);
        default:
            return (float)(firstQuadrantAngle - lbl_803E7A00);
    }
}
