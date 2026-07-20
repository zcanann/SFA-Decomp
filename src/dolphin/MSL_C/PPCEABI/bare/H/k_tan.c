#include "main/fsin16_approx_api.h"
#include "main/trig.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

extern float lbl_803E7C70;
extern float lbl_803E7C74;
extern float lbl_803E7C78;

float sqrtf_8029312c(float value) {
    float reciprocalSqrt;
    float halfValue;

    if (lbl_803E7C70 != value) {
        reciprocalSqrt = (float)__frsqrte(value);
        halfValue = lbl_803E7C74 * value;
        reciprocalSqrt = reciprocalSqrt * (lbl_803E7C78 - reciprocalSqrt * (halfValue * reciprocalSqrt));
        reciprocalSqrt = reciprocalSqrt * (lbl_803E7C78 - reciprocalSqrt * (halfValue * reciprocalSqrt));
        reciprocalSqrt = reciprocalSqrt * (lbl_803E7C78 - reciprocalSqrt * (halfValue * reciprocalSqrt));
        return reciprocalSqrt * value;
    }

    return lbl_803E7C70;
}

float sqrtf(float value) {
    float reciprocalSqrt;
    float halfValue;

    if (lbl_803E7C70 != value) {
        reciprocalSqrt = (float)__frsqrte(value);
        halfValue = lbl_803E7C74 * value;
        reciprocalSqrt = reciprocalSqrt * (lbl_803E7C78 - reciprocalSqrt * (halfValue * reciprocalSqrt));
        return reciprocalSqrt * value;
    }

    return lbl_803E7C70;
}

float invSqrt(float value) {
    float reciprocalSqrt;
    float halfValue;

    reciprocalSqrt = (float)__frsqrte(value);
    halfValue = lbl_803E7C74 * value;
    reciprocalSqrt = reciprocalSqrt * (lbl_803E7C78 - reciprocalSqrt * (halfValue * reciprocalSqrt));
    return reciprocalSqrt;
}
