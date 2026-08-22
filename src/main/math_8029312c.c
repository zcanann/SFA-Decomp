#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/math_8029312c.h"

extern const float sSqrtZero;
extern const float sSqrtHalf;
extern const float sSqrtThreeHalves;

float sqrtfHighPrecision(float value) {
    float reciprocalSqrt;
    float halfValue;

    if (sSqrtZero != value) {
        reciprocalSqrt = (float)__frsqrte(value);
        halfValue = sSqrtHalf * value;
        reciprocalSqrt = reciprocalSqrt * (sSqrtThreeHalves - reciprocalSqrt * (halfValue * reciprocalSqrt));
        reciprocalSqrt = reciprocalSqrt * (sSqrtThreeHalves - reciprocalSqrt * (halfValue * reciprocalSqrt));
        reciprocalSqrt = reciprocalSqrt * (sSqrtThreeHalves - reciprocalSqrt * (halfValue * reciprocalSqrt));
        return reciprocalSqrt * value;
    }

    return sSqrtZero;
}

float sqrtf(float value) {
    float reciprocalSqrt;
    float halfValue;

    if (sSqrtZero != value) {
        reciprocalSqrt = (float)__frsqrte(value);
        halfValue = sSqrtHalf * value;
        reciprocalSqrt = reciprocalSqrt * (sSqrtThreeHalves - reciprocalSqrt * (halfValue * reciprocalSqrt));
        return reciprocalSqrt * value;
    }

    return sSqrtZero;
}

float invSqrt(float value) {
    float reciprocalSqrt;
    float halfValue;

    reciprocalSqrt = (float)__frsqrte(value);
    halfValue = sSqrtHalf * value;
    reciprocalSqrt = reciprocalSqrt * (sSqrtThreeHalves - reciprocalSqrt * (halfValue * reciprocalSqrt));
    return reciprocalSqrt;
}

const float sSqrtZero = 0.0f;
const float sSqrtHalf = 0.5f;
const float sSqrtThreeHalves = 1.5f;
