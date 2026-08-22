#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/trig_float_helpers.h"

extern const float sAngleVec2FastSinLinear;
extern const float sAngleVec2FastSinCubic;
extern const float sAngleVec2FastCosBias;
extern const float sAngleVec2FastCosLinear;
extern const float sAngleVec2FastCosQuadratic;
extern const float sAngleVec2SinLinear;
extern const float sAngleVec2SinCubic;
extern const float sAngleVec2SinQuintic;
extern const float sAngleVec2CosBias;
extern const float sAngleVec2CosQuadratic;
extern const float sAngleVec2CosQuartic;
extern const float sAngleVec2CosSextic;
extern const float sAngleVec2PreciseSinLinear;
extern const float sAngleVec2PreciseSinCubic;
extern const float sAngleVec2PreciseSinQuintic;
extern const float sAngleVec2PreciseSinSeptic;
extern const float sAngleVec2PreciseCosQuadratic;
extern const float sAngleVec2PreciseCosQuartic;
extern const float sAngleVec2PreciseCosSextic;
extern const float sAngleVec2PreciseCosOctic;

float fastReciprocal(float value) {
    float reciprocal;

    reciprocal = __fres(value);
    reciprocal *= 2.0f - value * reciprocal;
    reciprocal *= 2.0f - value * reciprocal;

    return reciprocal;
}

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

void angleToVec2Fast(int angle, float* sinOut, float* cosOut) {
    s16 scaledAngleBits = (u16)angle << 1 << 1;
    float scaledAngle = fastCastS16ToFloat(&scaledAngleBits);
    float angleSquared = scaledAngle * scaledAngle;
    float sine = scaledAngle * (sAngleVec2FastSinCubic * angleSquared + sAngleVec2FastSinLinear);
    float cosine =
        angleSquared * (sAngleVec2FastCosQuadratic * angleSquared + sAngleVec2FastCosLinear) + sAngleVec2FastCosBias;

    STORE_SINCOS(angle, sine, cosine, sinOut, cosOut);
}

void angleToVec2(int angle, float* sinOut, float* cosOut) {
    s16 scaledAngleBits = (u16)angle << 1 << 1;
    float scaledAngle = fastCastS16ToFloat(&scaledAngleBits);
    float angleSquared = scaledAngle * scaledAngle;
    float sine =
        scaledAngle * ((sAngleVec2SinQuintic * angleSquared + sAngleVec2SinCubic) * angleSquared + sAngleVec2SinLinear);
    float cosine =
        ((sAngleVec2CosSextic * angleSquared + sAngleVec2CosQuartic) * angleSquared + sAngleVec2CosQuadratic) *
            angleSquared +
        sAngleVec2CosBias;

    STORE_SINCOS(angle, sine, cosine, sinOut, cosOut);
}

void angleToVec2Precise(int angle, float* sinOut, float* cosOut) {
    s16 scaledAngleBits = (u16)angle << 1 << 1;
    float scaledAngle = fastCastS16ToFloat(&scaledAngleBits);
    float angleSquared = scaledAngle * scaledAngle;
    float sine =
        scaledAngle * (((sAngleVec2PreciseSinSeptic * angleSquared + sAngleVec2PreciseSinQuintic) * angleSquared +
                        sAngleVec2PreciseSinCubic) *
                           angleSquared +
                       sAngleVec2PreciseSinLinear);
    float cosine = (sAngleVec2PreciseCosQuadratic +
                    ((sAngleVec2PreciseCosOctic * angleSquared + sAngleVec2PreciseCosSextic) * angleSquared +
                     sAngleVec2PreciseCosQuartic) *
                        angleSquared) *
                       angleSquared +
                   sAngleVec2CosBias;

    STORE_SINCOS(angle, sine, cosine, sinOut, cosOut);
}

const float sAngleVec2FastSinLinear = 0.000023945184f;
const float sAngleVec2FastSinCubic = -2.2078018e-15f;
const float sAngleVec2FastCosBias = 0.99999f;
const float sAngleVec2FastCosLinear = -2.8707542e-10f;
const float sAngleVec2FastCosQuadratic = 1.3332733e-20f;
const float sAngleVec2SinLinear = 0.00002396833f;
const float sAngleVec2SinCubic = -2.294029e-15f;
const float sAngleVec2SinQuintic = 6.424445e-26f;
const float sAngleVec2CosBias = 1.0f;
const float sAngleVec2CosQuadratic = -2.8724248e-10f;
const float sAngleVec2CosQuartic = 1.3747608e-20f;
const float sAngleVec2CosSextic = -2.575884e-31f;
const float sAngleVec2PreciseSinLinear = 0.000023968449f;
const float sAngleVec2PreciseSinCubic = -2.2949214e-15f;
const float sAngleVec2PreciseSinQuintic = 6.590636e-26f;
const float sAngleVec2PreciseSinSeptic = -8.8444e-37f;
const float sAngleVec2PreciseCosQuadratic = -2.8724328e-10f;
const float sAngleVec2PreciseCosQuartic = 1.3751435e-20f;
const float sAngleVec2PreciseCosSextic = -2.632911e-31f;
const float sAngleVec2PreciseCosOctic = 2.655e-42f;
