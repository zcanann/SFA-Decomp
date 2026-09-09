#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/trig_float_helpers.h"

#define STORE_SINCOS(angle, sine, cosine, sinOut, cosOut)                                                              \
    switch ((((u16)(angle)) + 0x2000) & 0xC000) {                                                                      \
    case 0x0000:                                                                                                       \
        *(sinOut) = (sine);                                                                                            \
        *(cosOut) = (cosine);                                                                                          \
        break;                                                                                                         \
    case 0x4000:                                                                                                       \
        *(sinOut) = (cosine);                                                                                          \
        *(cosOut) = -(sine);                                                                                           \
        break;                                                                                                         \
    case 0x8000:                                                                                                       \
        *(sinOut) = -(sine);                                                                                           \
        *(cosOut) = -(cosine);                                                                                         \
        break;                                                                                                         \
    default:                                                                                                           \
        *(sinOut) = -(cosine);                                                                                         \
        *(cosOut) = (sine);                                                                                            \
        break;                                                                                                         \
    }

/* Each routine seeds its sine/cosine polynomial accumulators with the
 * reduced angle and its square before restoring the full-angle quadrant. */
void angleToVec2Fast(int angle, float* sinOut, float* cosOut) {
    s16 scaledAngleBits = (u16)angle << 1 << 1;
    float sine = fastCastS16ToFloat(&scaledAngleBits);
    float cosine = sine * sine;
    sine = sine * (-2.2078018e-15f * cosine + 0.000023945184f);
    cosine = cosine * (1.3332733e-20f * cosine + -2.8707542e-10f) + 0.99999f;

    STORE_SINCOS(angle, sine, cosine, sinOut, cosOut);
}

void angleToVec2(int angle, float* sinOut, float* cosOut) {
    s16 scaledAngleBits = (u16)angle << 1 << 1;
    float sine = fastCastS16ToFloat(&scaledAngleBits);
    float cosine = sine * sine;
    sine = sine * (cosine * (6.424445e-26f * cosine + -2.294029e-15f) + 0.00002396833f);
    cosine =
        cosine * (cosine * (-2.575884e-31f * cosine + 1.3747608e-20f) + -2.8724248e-10f) + 1.0f;

    STORE_SINCOS(angle, sine, cosine, sinOut, cosOut);
}

void angleToVec2Precise(int angle, float* sinOut, float* cosOut) {
    s16 scaledAngleBits = (u16)angle << 1 << 1;
    float sine = fastCastS16ToFloat(&scaledAngleBits);
    float cosine = sine * sine;
    sine =
        sine * (cosine * (cosine * (-8.8444e-37f * cosine + 6.590636e-26f) + -2.2949214e-15f) +
                       0.000023968449f);
    cosine =
        cosine * (cosine * (cosine * (2.655e-42f * cosine + -2.632911e-31f) + 1.3751435e-20f) +
                        -2.8724328e-10f) +
        1.0f;

    STORE_SINCOS(angle, sine, cosine, sinOut, cosOut);
}
