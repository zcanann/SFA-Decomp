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

static inline u32 float_bits(const float *value) {
    return ((const FloatWord *)value)->bits;
}

float __kernel_cos(float y, float x) {
    float absX = __fabsf(x);
    float absY = __fabsf(y);
    float ratio;
    float ratioSquared;
    float angle;
    s32 signBits;

    if (absX > absY) {
        ratio = absY / absX;
        ratioSquared = ratio * ratio;
        angle = ratio * (lbl_803E7A0C * ratioSquared + lbl_803E7A08);
    } else {
        ratio = absX / absY;
        ratioSquared = ratio * ratio;
        angle = lbl_803E79C8 - ratio * (lbl_803E7A0C * ratioSquared + lbl_803E7A08);
    }

    signBits = (float_bits(&y) & 0x80000000) | ((float_bits(&x) & 0x80000000) >> 1);
    switch (signBits) {
        case 0x00000000:
            return angle;
        case 0x80000000:
            return -angle;
        case 0x40000000:
            return lbl_803E79E8 - angle;
        default:
            return angle - lbl_803E79E8;
    }
}

float atan2f(float y, float x) {
    float absX = __fabsf(x);
    float absY = __fabsf(y);
    float ratio;
    float ratioSquared;
    float angle;
    int signBits;

    if (absX > absY) {
        ratio = absY / absX;
        ratioSquared = ratio * ratio;
        angle = ratio * (((lbl_803E7A28 * ratioSquared + lbl_803E7A24) * ratioSquared + lbl_803E7A20) * ratioSquared + lbl_803E7A1C);
    } else {
        ratio = absX / absY;
        ratioSquared = ratio * ratio;
        angle = lbl_803E79C8 - ratio * (((lbl_803E7A28 * ratioSquared + lbl_803E7A24) * ratioSquared + lbl_803E7A20) * ratioSquared + lbl_803E7A1C);
    }

    signBits = (*(u32 *)&y & 0x80000000) | ((*(u32 *)&x & 0x80000000) >> 1);
    switch (signBits) {
        case 0x00000000:
            return angle;
        case 0x80000000:
            return -angle;
        case 0x40000000:
            return lbl_803E79E8 - angle;
        default:
            return angle - lbl_803E79E8;
    }
}

float fn_802925C4(float y, float x) {
    float absX = __fabsf(x);
    float absY = __fabsf(y);
    double ratio;
    double ratioSquared;
    double angle;
    int signBits;

    if (absX >= absY) {
        ratio = absY / absX;
        ratioSquared = ratio * ratio;
        angle = ratio * (((((((((((((((lbl_803E7AA8 * ratioSquared + lbl_803E7AA0) * ratioSquared + lbl_803E7A98) * ratioSquared + lbl_803E7A90) * ratioSquared
                       + lbl_803E7A88) * ratioSquared + lbl_803E7A80) * ratioSquared + lbl_803E7A78) * ratioSquared + lbl_803E7A70) * ratioSquared
                    + lbl_803E7A68) * ratioSquared + lbl_803E7A60) * ratioSquared + lbl_803E7A58) * ratioSquared + lbl_803E7A50) * ratioSquared
                 + lbl_803E7A48) * ratioSquared + lbl_803E7A40) * ratioSquared + lbl_803E7A38) * ratioSquared + lbl_803E7A30);
    } else {
        ratio = absX / absY;
        ratioSquared = ratio * ratio;
        angle = lbl_803E79E0 - ratio * (((((((((((((((lbl_803E7AA8 * ratioSquared + lbl_803E7AA0) * ratioSquared + lbl_803E7A98) * ratioSquared + lbl_803E7A90) * ratioSquared
                       + lbl_803E7A88) * ratioSquared + lbl_803E7A80) * ratioSquared + lbl_803E7A78) * ratioSquared + lbl_803E7A70) * ratioSquared
                    + lbl_803E7A68) * ratioSquared + lbl_803E7A60) * ratioSquared + lbl_803E7A58) * ratioSquared + lbl_803E7A50) * ratioSquared
                 + lbl_803E7A48) * ratioSquared + lbl_803E7A40) * ratioSquared + lbl_803E7A38) * ratioSquared + lbl_803E7A30);
    }

    signBits = (*(u32 *)&y & 0x80000000) | ((*(u32 *)&x & 0x80000000) >> 1);
    switch (signBits) {
        case 0x00000000:
            return (float)angle;
        case 0x80000000:
            return (float)-angle;
        case 0x40000000:
            return (float)(lbl_803E7A00 - angle);
        default:
            return (float)(angle - lbl_803E7A00);
    }
}
