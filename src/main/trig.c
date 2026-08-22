#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/fcos16_approx_api.h"
#include "main/trig.h"
#include "main/fsin16_approx_api.h"

extern const float sTrigApproxCosBias;
extern const float sTrigApproxCosLinear;
extern const float sTrigApproxCosQuadratic;
extern const float sTrigApproxSinLinear;
extern const float sTrigApproxSinCubic;

float fsin16Approx(int angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float x = fastCastS16ToFloat(&scaledAngleBits);
    float x2 = x * x;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return x * (sTrigApproxSinCubic * x2 + sTrigApproxSinLinear);
    case 0x2000:
    case 0x4000:
        return x2 * (sTrigApproxCosQuadratic * x2 + sTrigApproxCosLinear) + sTrigApproxCosBias;
    case 0x6000:
    case 0x8000:
        return -(x * (sTrigApproxSinCubic * x2 + sTrigApproxSinLinear));
    default:
        return -(x2 * (sTrigApproxCosQuadratic * x2 + sTrigApproxCosLinear) + sTrigApproxCosBias);
    }
}

float fsin16(int angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float x = fastCastS16ToFloat(&scaledAngleBits);
    float x2 = x * x;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return x * (x2 * (6.424445e-26f * x2 + -2.294029e-15f) + 0.00002396833f);
    case 0x2000:
    case 0x4000:
        return (x2 * (x2 * (-2.575884e-31f * x2 + 1.3747608e-20f) + -2.8724248e-10f) + 1.0f);
    case 0x6000:
    case 0x8000:
        return -(x * (x2 * (6.424445e-26f * x2 + -2.294029e-15f) + 0.00002396833f));
    default:
        return -(x2 * (x2 * (-2.575884e-31f * x2 + 1.3747608e-20f) + -2.8724248e-10f) + 1.0f);
    }
}

float fsin16Precise(int angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y * (y2 * (y2 * (-8.8444e-37f * y2 + 6.590636e-26f) + -2.2949214e-15f) + 0.000023968449f);
    case 0x2000:
    case 0x4000:
        return y2 * (y2 * (y2 * (2.655e-42f * y2 + -2.632911e-31f) + 1.3751435e-20f) + -2.8724328e-10f) + 1.0f;
    case 0x6000:
    case 0x8000:
        return -(y * (y2 * (y2 * (-8.8444e-37f * y2 + 6.590636e-26f) + -2.2949214e-15f) + 0.000023968449f));
    default:
        return -(y2 * (y2 * (y2 * (2.655e-42f * y2 + -2.632911e-31f) + 1.3751435e-20f) + -2.8724328e-10f) + 1.0f);
    }
}

float fsin16HighPrecision(int angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float reducedFloat = fastCastS16ToFloat(&scaledAngleBits);
    double reducedAngle = 0.000023968449810713143 * reducedFloat;
    double reducedSquared = reducedAngle * reducedAngle;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return (float)(reducedAngle *
                       (reducedSquared *
                            (reducedSquared *
                                 (reducedSquared * (reducedSquared * (-0.00000002473889883359452 * reducedSquared +
                                                                      0.0000027554973093759717) +
                                                    -0.00019841261464659544) +
                                  0.008333333318980809) +
                             -0.16666666666563978) +
                        0.9999999999999805));
    case 0x2000:
    case 0x4000:
        return (float)((
            reducedSquared *
                (reducedSquared *
                     (reducedSquared * (reducedSquared * (reducedSquared * (2.048770813211803e-09 * reducedSquared +
                                                                            -0.0000002755268200651971) +
                                                          0.000024801561642773723) +
                                        -0.001388888881954176) +
                      0.041666666665824886) +
                 -0.4999999999999672) +
            1.0));
    case 0x6000:
    case 0x8000:
        return (float)(-(
            reducedAngle *
            (reducedSquared *
                 (reducedSquared * (reducedSquared * (reducedSquared * (-0.00000002473889883359452 * reducedSquared +
                                                                        0.0000027554973093759717) +
                                                      -0.00019841261464659544) +
                                    0.008333333318980809) +
                  -0.16666666666563978) +
             0.9999999999999805)));
    default:
        return (float)(-(
            reducedSquared *
                (reducedSquared *
                     (reducedSquared * (reducedSquared * (reducedSquared * (2.048770813211803e-09 * reducedSquared +
                                                                            -0.0000002755268200651971) +
                                                          0.000024801561642773723) +
                                        -0.001388888881954176) +
                      0.041666666665824886) +
                 -0.4999999999999672) +
            1.0));
    }
}

float fcos16Approx(int angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y2 * (sTrigApproxCosQuadratic * y2 + sTrigApproxCosLinear) + sTrigApproxCosBias;
    case 0x2000:
    case 0x4000:
        return -(y * (sTrigApproxSinCubic * y2 + sTrigApproxSinLinear));
    case 0x6000:
    case 0x8000:
        return -(y2 * (sTrigApproxCosQuadratic * y2 + sTrigApproxCosLinear) + sTrigApproxCosBias);
    default:
        return y * (sTrigApproxSinCubic * y2 + sTrigApproxSinLinear);
    }
}

const float sTrigApproxCosBias = 0.99999f;
const float sTrigApproxCosLinear = -2.8707542e-10f;
const float sTrigApproxCosQuadratic = 1.3332733e-20f;
const float sTrigApproxSinLinear = 0.000023945184f;
const float sTrigApproxSinCubic = -2.2078018e-15f;

float fcos16(int angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y2 * (y2 * (-2.575884e-31f * y2 + 1.3747608e-20f) + -2.8724248e-10f) + 1.0f;
    case 0x2000:
    case 0x4000:
        return -(y * (y2 * (6.424445e-26f * y2 + -2.294029e-15f) + 0.00002396833f));
    case 0x6000:
    case 0x8000:
        return -(y2 * (y2 * (-2.575884e-31f * y2 + 1.3747608e-20f) + -2.8724248e-10f) + 1.0f);
    default:
        return y * (y2 * (6.424445e-26f * y2 + -2.294029e-15f) + 0.00002396833f);
    }
}

float fcos16Precise(int angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y2 * (y2 * (y2 * (2.655e-42f * y2 + -2.632911e-31f) + 1.3751435e-20f) + -2.8724328e-10f) + 1.0f;
    case 0x2000:
    case 0x4000:
        return -(y * (y2 * (y2 * (-8.8444e-37f * y2 + 6.590636e-26f) + -2.2949214e-15f) + 0.000023968449f));
    case 0x6000:
    case 0x8000:
        return -(y2 * (y2 * (y2 * (2.655e-42f * y2 + -2.632911e-31f) + 1.3751435e-20f) + -2.8724328e-10f) + 1.0f);
    default:
        return y * (y2 * (y2 * (-8.8444e-37f * y2 + 6.590636e-26f) + -2.2949214e-15f) + 0.000023968449f);
    }
}

float fcos16HighPrecision(int angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float reducedFloat = fastCastS16ToFloat(&scaledAngleBits);
    double reducedAngle = 0.000023968449810713143 * reducedFloat;
    double reducedSquared = reducedAngle * reducedAngle;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return (float)((
            reducedSquared *
                (reducedSquared *
                     (reducedSquared * (reducedSquared * (reducedSquared * (2.048770813211803e-09 * reducedSquared +
                                                                            -0.0000002755268200651971) +
                                                          0.000024801561642773723) +
                                        -0.001388888881954176) +
                      0.041666666665824886) +
                 -0.4999999999999672) +
            1.0));
    case 0x2000:
    case 0x4000:
        return (float)(-(
            reducedAngle *
            (reducedSquared *
                 (reducedSquared * (reducedSquared * (reducedSquared * (-0.00000002473889883359452 * reducedSquared +
                                                                        0.0000027554973093759717) +
                                                      -0.00019841261464659544) +
                                    0.008333333318980809) +
                  -0.16666666666563978) +
             0.9999999999999805)));
    case 0x6000:
    case 0x8000:
        return (float)(-(
            reducedSquared *
                (reducedSquared *
                     (reducedSquared * (reducedSquared * (reducedSquared * (2.048770813211803e-09 * reducedSquared +
                                                                            -0.0000002755268200651971) +
                                                          0.000024801561642773723) +
                                        -0.001388888881954176) +
                      0.041666666665824886) +
                 -0.4999999999999672) +
            1.0));
    default:
        return (float)(reducedAngle *
                       (reducedSquared *
                            (reducedSquared *
                                 (reducedSquared * (reducedSquared * (-0.00000002473889883359452 * reducedSquared +
                                                                      0.0000027554973093759717) +
                                                    -0.00019841261464659544) +
                                  0.008333333318980809) +
                             -0.16666666666563978) +
                        0.9999999999999805));
    }
}
