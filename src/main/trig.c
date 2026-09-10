#include "main/trig.h"
#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

/* Address-based reads retain these named constants without duplicate literals. */
const float sTrigApproxCosBias = 0.99999f;
const float sTrigApproxCosLinear = -2.8707542e-10f;
const float sTrigApproxCosQuadratic = 1.3332733e-20f;
const float sTrigApproxSinLinear = 0.000023945184f;
const float sTrigApproxSinCubic = -2.2078018e-15f;
const float sTrigSinLinear = 0.00002396833f;
const float sTrigSinCubic = -2.294029e-15f;
const float sTrigSinQuintic = 6.424445e-26f;
const float sTrigUnit = 1.0f;
const float sTrigCosQuadratic = -2.8724248e-10f;
const float sTrigCosQuartic = 1.3747608e-20f;
const float sTrigCosSextic = -2.575884e-31f;
const float sTrigPreciseSinLinear = 0.000023968449f;
const float sTrigPreciseSinCubic = -2.2949214e-15f;
const float sTrigPreciseSinQuintic = 6.590636e-26f;
const float sTrigPreciseSinSeptic = -8.8444e-37f;
const float sTrigPreciseCosQuadratic = -2.8724328e-10f;
const float sTrigPreciseCosQuartic = 1.3751435e-20f;
const float sTrigPreciseCosSextic = -2.632911e-31f;
const float sTrigPreciseCosOctic = 2.655e-42f;
const double sTrigHighPrecisionAngleScale = 0.000023968449810713143;
const double sTrigHighPrecisionSinCoeff1 = 0.9999999999999805;
const double sTrigHighPrecisionSinCoeff3 = -0.16666666666563978;
const double sTrigHighPrecisionSinCoeff5 = 0.008333333318980809;
const double sTrigHighPrecisionSinCoeff7 = -0.00019841261464659544;
const double sTrigHighPrecisionSinCoeff9 = 0.0000027554973093759717;
const double sTrigHighPrecisionSinCoeff11 = -0.00000002473889883359452;
const double sTrigHighPrecisionCosCoeff0 = 1.0;
const double sTrigHighPrecisionCosCoeff2 = -0.4999999999999672;
const double sTrigHighPrecisionCosCoeff4 = 0.041666666665824886;
const double sTrigHighPrecisionCosCoeff6 = -0.001388888881954176;
const double sTrigHighPrecisionCosCoeff8 = 0.000024801561642773723;
const double sTrigHighPrecisionCosCoeff10 = -0.0000002755268200651971;
const double sTrigHighPrecisionCosCoeff12 = 2.048770813211803e-09;

float fsin16Approx(u16 angle) {
    s16 scaledAngleBits = (s16)(int)(((u16)angle << 2) & 0x3FFFC);
    float x = fastCastS16ToFloat(&scaledAngleBits);
    float x2 = x * x;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return x * (*(const float*)&sTrigApproxSinCubic * x2 + *(const float*)&sTrigApproxSinLinear);
    case 0x2000:
    case 0x4000:
        return x2 * (*(const float*)&sTrigApproxCosQuadratic * x2 + *(const float*)&sTrigApproxCosLinear) +
               *(const float*)&sTrigApproxCosBias;
    case 0x6000:
    case 0x8000:
        return -(x * (*(const float*)&sTrigApproxSinCubic * x2 + *(const float*)&sTrigApproxSinLinear));
    default:
        return -(x2 * (*(const float*)&sTrigApproxCosQuadratic * x2 + *(const float*)&sTrigApproxCosLinear) +
                 *(const float*)&sTrigApproxCosBias);
    }
}

float fsin16(int angle) {
    s16 scaledAngleBits = (s16)(int)(((u16)angle << 2) & 0x3FFFC);
    float x = fastCastS16ToFloat(&scaledAngleBits);
    float x2 = x * x;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return x * (x2 * (*(const float*)&sTrigSinQuintic * x2 + *(const float*)&sTrigSinCubic) +
                    *(const float*)&sTrigSinLinear);
    case 0x2000:
    case 0x4000:
        return (x2 * (x2 * (*(const float*)&sTrigCosSextic * x2 + *(const float*)&sTrigCosQuartic) +
                      *(const float*)&sTrigCosQuadratic) +
                *(const float*)&sTrigUnit);
    case 0x6000:
    case 0x8000:
        return -(x * (x2 * (*(const float*)&sTrigSinQuintic * x2 + *(const float*)&sTrigSinCubic) +
                      *(const float*)&sTrigSinLinear));
    default:
        return -(x2 * (x2 * (*(const float*)&sTrigCosSextic * x2 + *(const float*)&sTrigCosQuartic) +
                       *(const float*)&sTrigCosQuadratic) +
                 *(const float*)&sTrigUnit);
    }
}

float fsin16Precise(int angle) {
    s16 scaledAngleBits = (s16)(int)(((u16)angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y * (y2 * (y2 * (*(const float*)&sTrigPreciseSinSeptic * y2 + *(const float*)&sTrigPreciseSinQuintic) +
                          *(const float*)&sTrigPreciseSinCubic) +
                    *(const float*)&sTrigPreciseSinLinear);
    case 0x2000:
    case 0x4000:
        return y2 * (y2 * (y2 * (*(const float*)&sTrigPreciseCosOctic * y2 + *(const float*)&sTrigPreciseCosSextic) +
                           *(const float*)&sTrigPreciseCosQuartic) +
                     *(const float*)&sTrigPreciseCosQuadratic) +
               *(const float*)&sTrigUnit;
    case 0x6000:
    case 0x8000:
        return -(y * (y2 * (y2 * (*(const float*)&sTrigPreciseSinSeptic * y2 + *(const float*)&sTrigPreciseSinQuintic) +
                            *(const float*)&sTrigPreciseSinCubic) +
                      *(const float*)&sTrigPreciseSinLinear));
    default:
        return -(y2 * (y2 * (y2 * (*(const float*)&sTrigPreciseCosOctic * y2 + *(const float*)&sTrigPreciseCosSextic) +
                             *(const float*)&sTrigPreciseCosQuartic) +
                       *(const float*)&sTrigPreciseCosQuadratic) +
                 *(const float*)&sTrigUnit);
    }
}

float fsin16HighPrecision(int angle) {
    s16 scaledAngleBits = (s16)(int)(((u16)angle << 2) & 0x3FFFC);
    double reducedAngle = *(const double*)&sTrigHighPrecisionAngleScale * fastCastS16ToFloat(&scaledAngleBits);
    double reducedSquared = reducedAngle * reducedAngle;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return (float)(reducedAngle *
                       (reducedSquared *
                            (reducedSquared *
                                 (reducedSquared * (reducedSquared * (*(const double*)&sTrigHighPrecisionSinCoeff11 *
                                                                          reducedSquared +
                                                                      *(const double*)&sTrigHighPrecisionSinCoeff9) +
                                                    *(const double*)&sTrigHighPrecisionSinCoeff7) +
                                  *(const double*)&sTrigHighPrecisionSinCoeff5) +
                             *(const double*)&sTrigHighPrecisionSinCoeff3) +
                        *(const double*)&sTrigHighPrecisionSinCoeff1));
    case 0x2000:
    case 0x4000:
        return (float)((
            reducedSquared *
                (reducedSquared *
                     (reducedSquared *
                          (reducedSquared *
                               (reducedSquared * (*(const double*)&sTrigHighPrecisionCosCoeff12 * reducedSquared +
                                                  *(const double*)&sTrigHighPrecisionCosCoeff10) +
                                *(const double*)&sTrigHighPrecisionCosCoeff8) +
                           *(const double*)&sTrigHighPrecisionCosCoeff6) +
                      *(const double*)&sTrigHighPrecisionCosCoeff4) +
                 *(const double*)&sTrigHighPrecisionCosCoeff2) +
            *(const double*)&sTrigHighPrecisionCosCoeff0));
    case 0x6000:
    case 0x8000:
        return (float)(-(
            reducedAngle *
            (reducedSquared *
                 (reducedSquared * (reducedSquared * (reducedSquared * (*(const double*)&sTrigHighPrecisionSinCoeff11 *
                                                                            reducedSquared +
                                                                        *(const double*)&sTrigHighPrecisionSinCoeff9) +
                                                      *(const double*)&sTrigHighPrecisionSinCoeff7) +
                                    *(const double*)&sTrigHighPrecisionSinCoeff5) +
                  *(const double*)&sTrigHighPrecisionSinCoeff3) +
             *(const double*)&sTrigHighPrecisionSinCoeff1)));
    default:
        return (float)(-(
            reducedSquared *
                (reducedSquared *
                     (reducedSquared *
                          (reducedSquared *
                               (reducedSquared * (*(const double*)&sTrigHighPrecisionCosCoeff12 * reducedSquared +
                                                  *(const double*)&sTrigHighPrecisionCosCoeff10) +
                                *(const double*)&sTrigHighPrecisionCosCoeff8) +
                           *(const double*)&sTrigHighPrecisionCosCoeff6) +
                      *(const double*)&sTrigHighPrecisionCosCoeff4) +
                 *(const double*)&sTrigHighPrecisionCosCoeff2) +
            *(const double*)&sTrigHighPrecisionCosCoeff0));
    }
}

float fcos16Approx(u16 angle) {
    s16 scaledAngleBits = (s16)(int)(((u16)angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y2 * (*(const float*)&sTrigApproxCosQuadratic * y2 + *(const float*)&sTrigApproxCosLinear) +
               *(const float*)&sTrigApproxCosBias;
    case 0x2000:
    case 0x4000:
        return -(y * (*(const float*)&sTrigApproxSinCubic * y2 + *(const float*)&sTrigApproxSinLinear));
    case 0x6000:
    case 0x8000:
        return -(y2 * (*(const float*)&sTrigApproxCosQuadratic * y2 + *(const float*)&sTrigApproxCosLinear) +
                 *(const float*)&sTrigApproxCosBias);
    default:
        return y * (*(const float*)&sTrigApproxSinCubic * y2 + *(const float*)&sTrigApproxSinLinear);
    }
}

float fcos16(int angle) {
    s16 scaledAngleBits = (s16)(int)(((u16)angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y2 * (y2 * (*(const float*)&sTrigCosSextic * y2 + *(const float*)&sTrigCosQuartic) +
                     *(const float*)&sTrigCosQuadratic) +
               *(const float*)&sTrigUnit;
    case 0x2000:
    case 0x4000:
        return -(y * (y2 * (*(const float*)&sTrigSinQuintic * y2 + *(const float*)&sTrigSinCubic) +
                      *(const float*)&sTrigSinLinear));
    case 0x6000:
    case 0x8000:
        return -(y2 * (y2 * (*(const float*)&sTrigCosSextic * y2 + *(const float*)&sTrigCosQuartic) +
                       *(const float*)&sTrigCosQuadratic) +
                 *(const float*)&sTrigUnit);
    default:
        return y * (y2 * (*(const float*)&sTrigSinQuintic * y2 + *(const float*)&sTrigSinCubic) +
                    *(const float*)&sTrigSinLinear);
    }
}

float fcos16Precise(int angle) {
    s16 scaledAngleBits = (s16)(int)(((u16)angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y2 * (y2 * (y2 * (*(const float*)&sTrigPreciseCosOctic * y2 + *(const float*)&sTrigPreciseCosSextic) +
                           *(const float*)&sTrigPreciseCosQuartic) +
                     *(const float*)&sTrigPreciseCosQuadratic) +
               *(const float*)&sTrigUnit;
    case 0x2000:
    case 0x4000:
        return -(y * (y2 * (y2 * (*(const float*)&sTrigPreciseSinSeptic * y2 + *(const float*)&sTrigPreciseSinQuintic) +
                            *(const float*)&sTrigPreciseSinCubic) +
                      *(const float*)&sTrigPreciseSinLinear));
    case 0x6000:
    case 0x8000:
        return -(y2 * (y2 * (y2 * (*(const float*)&sTrigPreciseCosOctic * y2 + *(const float*)&sTrigPreciseCosSextic) +
                             *(const float*)&sTrigPreciseCosQuartic) +
                       *(const float*)&sTrigPreciseCosQuadratic) +
                 *(const float*)&sTrigUnit);
    default:
        return y * (y2 * (y2 * (*(const float*)&sTrigPreciseSinSeptic * y2 + *(const float*)&sTrigPreciseSinQuintic) +
                          *(const float*)&sTrigPreciseSinCubic) +
                    *(const float*)&sTrigPreciseSinLinear);
    }
}

float fcos16HighPrecision(int angle) {
    s16 scaledAngleBits = (s16)(int)(((u16)angle << 2) & 0x3FFFC);
    double reducedAngle = *(const double*)&sTrigHighPrecisionAngleScale * fastCastS16ToFloat(&scaledAngleBits);
    double reducedSquared = reducedAngle * reducedAngle;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return (float)((
            reducedSquared *
                (reducedSquared *
                     (reducedSquared *
                          (reducedSquared *
                               (reducedSquared * (*(const double*)&sTrigHighPrecisionCosCoeff12 * reducedSquared +
                                                  *(const double*)&sTrigHighPrecisionCosCoeff10) +
                                *(const double*)&sTrigHighPrecisionCosCoeff8) +
                           *(const double*)&sTrigHighPrecisionCosCoeff6) +
                      *(const double*)&sTrigHighPrecisionCosCoeff4) +
                 *(const double*)&sTrigHighPrecisionCosCoeff2) +
            *(const double*)&sTrigHighPrecisionCosCoeff0));
    case 0x2000:
    case 0x4000:
        return (float)(-(
            reducedAngle *
            (reducedSquared *
                 (reducedSquared * (reducedSquared * (reducedSquared * (*(const double*)&sTrigHighPrecisionSinCoeff11 *
                                                                            reducedSquared +
                                                                        *(const double*)&sTrigHighPrecisionSinCoeff9) +
                                                      *(const double*)&sTrigHighPrecisionSinCoeff7) +
                                    *(const double*)&sTrigHighPrecisionSinCoeff5) +
                  *(const double*)&sTrigHighPrecisionSinCoeff3) +
             *(const double*)&sTrigHighPrecisionSinCoeff1)));
    case 0x6000:
    case 0x8000:
        return (float)(-(
            reducedSquared *
                (reducedSquared *
                     (reducedSquared *
                          (reducedSquared *
                               (reducedSquared * (*(const double*)&sTrigHighPrecisionCosCoeff12 * reducedSquared +
                                                  *(const double*)&sTrigHighPrecisionCosCoeff10) +
                                *(const double*)&sTrigHighPrecisionCosCoeff8) +
                           *(const double*)&sTrigHighPrecisionCosCoeff6) +
                      *(const double*)&sTrigHighPrecisionCosCoeff4) +
                 *(const double*)&sTrigHighPrecisionCosCoeff2) +
            *(const double*)&sTrigHighPrecisionCosCoeff0));
    default:
        return (float)(reducedAngle *
                       (reducedSquared *
                            (reducedSquared *
                                 (reducedSquared * (reducedSquared * (*(const double*)&sTrigHighPrecisionSinCoeff11 *
                                                                          reducedSquared +
                                                                      *(const double*)&sTrigHighPrecisionSinCoeff9) +
                                                    *(const double*)&sTrigHighPrecisionSinCoeff7) +
                                  *(const double*)&sTrigHighPrecisionSinCoeff5) +
                             *(const double*)&sTrigHighPrecisionSinCoeff3) +
                        *(const double*)&sTrigHighPrecisionSinCoeff1));
    }
}
