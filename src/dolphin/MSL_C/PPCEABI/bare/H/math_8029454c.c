#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

extern const float lbl_803E7E18;
extern const float lbl_803E7E1C;
extern const float lbl_803E7E20;
extern const float lbl_803E7E24;
extern const float lbl_803E7E28;
extern const float lbl_803E7E2C;

float mathTanf(float angle) {
    u16 quadrant;
    float reducedAngle = trigReduceQuadrant(&quadrant, angle);
    float reducedSquared = reducedAngle * reducedAngle;
    float tangent = reducedAngle *
                    (((lbl_803E7E2C * reducedSquared + lbl_803E7E28) * reducedSquared + lbl_803E7E24) *
                         reducedSquared +
                     lbl_803E7E20);

    if (quadrant & 2) {
        tangent = lbl_803E7E18 / tangent;
    }

    if (angle >= lbl_803E7E1C) {
        return tangent;
    }
    return -tangent;
}

float fn_802945E0(float value) {
    u32 rawBits;
    float normalizedMantissa;
    float exponentAsFloat;
    s16 exponent;

    rawBits = *(u32*)&value;
    exponent = (s16)(((rawBits >> 23) & 0xFF) - 128);
    *(u32*)&normalizedMantissa = (rawBits & 0x7FFFFF) | 0x3F800000;

    exponentAsFloat = fastCastS16ToFloat(&exponent);
    return normalizedMantissa + exponentAsFloat;
}

const float lbl_803E7E18 = -1.0f;
const float lbl_803E7E1C = 0.0f;
const float lbl_803E7E20 = 0.785224974155426f;
const float lbl_803E7E24 = 0.16370797157287598f;
const float lbl_803E7E28 = 0.03238091617822647f;
const float lbl_803E7E2C = 0.018663575872778893f;
