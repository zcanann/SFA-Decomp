#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

extern const float lbl_803E7E18;
extern const float lbl_803E7E1C;
extern const float lbl_803E7E20;
extern const float lbl_803E7E24;
extern const float lbl_803E7E28;
extern const float lbl_803E7E2C;

float fn_8029454C(float x) {
    u16 n;
    float y = trigReduceQuadrant(&n, x);
    float y2 = y * y;
    float result = y * (((lbl_803E7E2C * y2 + lbl_803E7E28) * y2 + lbl_803E7E24) * y2 + lbl_803E7E20);

    if (n & 2) {
        result = lbl_803E7E18 / result;
    }

    if (x >= lbl_803E7E1C) {
        return result;
    }
    return -result;
}

float fn_802945E0(float x) {
    u32 bits;
    float mantissa;
    float tail;
    s16 exponent;

    bits = *(u32*)&x;
    exponent = (s16)(((bits >> 23) & 0xFF) - 128);
    *(u32*)&mantissa = (bits & 0x7FFFFF) | 0x3F800000;

    tail = fastCastS16ToFloat(&exponent);
    return mantissa + tail;
}

const float lbl_803E7E18 = -1.0f;
const float lbl_803E7E1C = 0.0f;
const float lbl_803E7E20 = 0.785224974155426f;
const float lbl_803E7E24 = 0.16370797157287598f;
const float lbl_803E7E28 = 0.03238091617822647f;
const float lbl_803E7E2C = 0.018663575872778893f;
