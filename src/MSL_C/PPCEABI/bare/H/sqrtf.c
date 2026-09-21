#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "MSL_C/PPCEABI/bare/H/sqrtf.h"

float sqrtfHighPrecision(float value) {
    float reciprocalSqrt;
    float halfValue;

    if (0.0f != value) {
        reciprocalSqrt = (float)__frsqrte(value);
        halfValue = 0.5f * value;
        reciprocalSqrt = reciprocalSqrt * (1.5f - reciprocalSqrt * (halfValue * reciprocalSqrt));
        reciprocalSqrt = reciprocalSqrt * (1.5f - reciprocalSqrt * (halfValue * reciprocalSqrt));
        reciprocalSqrt = reciprocalSqrt * (1.5f - reciprocalSqrt * (halfValue * reciprocalSqrt));
        return reciprocalSqrt * value;
    }

    return 0.0f;
}

float sqrtf(float value) {
    float reciprocalSqrt;
    float halfValue;

    if (0.0f != value) {
        reciprocalSqrt = (float)__frsqrte(value);
        halfValue = 0.5f * value;
        reciprocalSqrt = reciprocalSqrt * (1.5f - reciprocalSqrt * (halfValue * reciprocalSqrt));
        return reciprocalSqrt * value;
    }

    return 0.0f;
}

float invSqrt(float value) {
    float reciprocalSqrt;
    float halfValue;

    reciprocalSqrt = (float)__frsqrte(value);
    halfValue = 0.5f * value;
    reciprocalSqrt = reciprocalSqrt * (1.5f - reciprocalSqrt * (halfValue * reciprocalSqrt));
    return reciprocalSqrt;
}
