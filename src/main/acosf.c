#include "dolphin/MSL_C/PPCEABI/bare/H/k_tan.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
extern float lbl_803E79C0;
extern float lbl_803E79C4;
extern float lbl_803E79C8;
extern float lbl_803E79CC;
extern float lbl_803E79D0;
extern float lbl_803E79D4;
extern float lbl_803E79D8;
extern float lbl_803E79E8;
extern float lbl_803E79EC;
extern float lbl_803E79F0;
extern float lbl_803E79F4;
extern float lbl_803E79F8;
extern float lbl_803E79FC;
extern double lbl_803E79E0;
extern float lbl_803E7A10;
extern float lbl_803E7A14;
extern float lbl_803E7A18;
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
extern double lbl_803E7AB0;


float __kernel_sin(float value) {
    float absoluteValue = __fabsf(value);
    float reduced;
    float polynomial;
    float root;

    if (absoluteValue <= lbl_803E79C0) {
        reduced = value * value;
        return value * (lbl_803E79D4 * reduced + lbl_803E79D0);
    }

    reduced = lbl_803E79C0 - lbl_803E79C0 * absoluteValue;
    root = sqrtf_8029312c(reduced);
    polynomial = root * (lbl_803E79D4 * reduced + lbl_803E79D0);
    if (value >= lbl_803E79C4) {
        return lbl_803E79C8 - lbl_803E79CC * polynomial;
    }
    return lbl_803E79CC * polynomial - lbl_803E79C8;
}

float fn_80291FF4(float value) {
    float absoluteValue = __fabsf(value);
    float reduced;
    float polynomial;
    float root;

    if (absoluteValue <= lbl_803E79C0) {
        reduced = value * value;
        return lbl_803E79C8 - value * (lbl_803E79D4 * reduced + lbl_803E79D0);
    }

    reduced = lbl_803E79C0 - lbl_803E79C0 * absoluteValue;
    root = sqrtf_8029312c(reduced);
    polynomial = root * (lbl_803E79D4 * reduced + lbl_803E79D0);
    if (value >= lbl_803E79C4) {
        return lbl_803E79CC * polynomial;
    }
    return lbl_803E79E8 - lbl_803E79CC * polynomial;
}

float acosf(float value) {
    float absoluteValue = __fabsf(value);
    float reduced;
    float polynomial;
    float root;

    if (absoluteValue <= lbl_803E79C0) {
        reduced = value * value;
        return lbl_803E79C8 - value * (((((lbl_803E79FC * reduced + lbl_803E79F8) * reduced + lbl_803E79F4) * reduced
                                      + lbl_803E79F0) * reduced + lbl_803E79EC) * reduced + lbl_803E79D8);
    }

    reduced = lbl_803E79C0 - lbl_803E79C0 * absoluteValue;
    root = sqrtf_8029312c(reduced);
    polynomial = root
        * (((((lbl_803E79FC * reduced + lbl_803E79F8) * reduced + lbl_803E79F4) * reduced + lbl_803E79F0) * reduced
            + lbl_803E79EC) * reduced + lbl_803E79D8);
    if (value >= lbl_803E79C4) {
        return lbl_803E79CC * polynomial;
    }
    return lbl_803E79E8 - lbl_803E79CC * polynomial;
}

float fn_80292194(float value) {
    float absoluteValue = __fabsf(value);
    float reciprocal;
    float squared;
    float polynomial;
    float positiveResult;
    float negativeResult;

    if (absoluteValue <= lbl_803E79D8) {
        squared = value * value;
        return value * ((lbl_803E7A18 * squared + lbl_803E7A14) * squared + lbl_803E7A10);
    }

    reciprocal = fn_80292DEC(absoluteValue);
    squared = reciprocal * reciprocal;
    polynomial = (lbl_803E7A18 * squared + lbl_803E7A14) * squared + lbl_803E7A10;
    positiveResult = lbl_803E79C8 - reciprocal * polynomial;
    negativeResult = reciprocal * polynomial - lbl_803E79C8;
    if (value >= lbl_803E79C4) {
        return positiveResult;
    }
    return negativeResult;
}

float fn_80292248(float value) {
    float absoluteValue = __fabsf(value);
    double reduced;
    double squared;
    float result;

    if (absoluteValue <= lbl_803E79D8) {
        squared = value * value;
        return (float)(value * (((((((((((((((lbl_803E7AA8 * squared + lbl_803E7AA0) * squared + lbl_803E7A98) * squared
                                       + lbl_803E7A90) * squared + lbl_803E7A88) * squared + lbl_803E7A80) * squared
                                    + lbl_803E7A78) * squared + lbl_803E7A70) * squared + lbl_803E7A68) * squared
                                 + lbl_803E7A60) * squared + lbl_803E7A58) * squared + lbl_803E7A50) * squared
                              + lbl_803E7A48) * squared + lbl_803E7A40) * squared + lbl_803E7A38) * squared
                           + lbl_803E7A30));
    }

    squared = (reduced = lbl_803E7AB0 / absoluteValue) * reduced;
    result = (float)(lbl_803E79E0
                     - reduced * (((((((((((((((lbl_803E7AA8 * squared + lbl_803E7AA0) * squared + lbl_803E7A98) * squared
                                        + lbl_803E7A90) * squared + lbl_803E7A88) * squared + lbl_803E7A80) * squared
                                     + lbl_803E7A78) * squared + lbl_803E7A70) * squared + lbl_803E7A68) * squared
                                  + lbl_803E7A60) * squared + lbl_803E7A58) * squared + lbl_803E7A50) * squared
                               + lbl_803E7A48) * squared + lbl_803E7A40) * squared + lbl_803E7A38) * squared
                            + lbl_803E7A30));
    if (value >= lbl_803E79C4) {
        return result;
    }
    return -result;
}
