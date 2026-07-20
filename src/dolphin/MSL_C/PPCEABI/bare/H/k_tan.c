#include "main/trig_ext.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

extern float lbl_803E7C70;
extern float lbl_803E7C74;
extern float lbl_803E7C78;

float sqrtf_8029312c(float x) {
    float guess;
    float half;

    if (lbl_803E7C70 != x) {
        guess = (float)__frsqrte(x);
        half = lbl_803E7C74 * x;
        guess = guess * (lbl_803E7C78 - guess * (half * guess));
        guess = guess * (lbl_803E7C78 - guess * (half * guess));
        guess = guess * (lbl_803E7C78 - guess * (half * guess));
        return guess * x;
    }

    return lbl_803E7C70;
}

float sqrtf(float x) {
    float guess;
    float half;

    if (lbl_803E7C70 != x) {
        guess = (float)__frsqrte(x);
        half = lbl_803E7C74 * x;
        guess = guess * (lbl_803E7C78 - guess * (half * guess));
        return guess * x;
    }

    return lbl_803E7C70;
}

float invSqrt(float x) {
    float guess;
    float half;

    guess = (float)__frsqrte(x);
    half = lbl_803E7C74 * x;
    guess = guess * (lbl_803E7C78 - guess * (half * guess));
    return guess;
}
