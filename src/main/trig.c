#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

extern const float sTrigApproxCosBias;
extern const float sTrigApproxCosLinear;
extern const float sTrigApproxCosQuadratic;
extern const float sTrigApproxSinLinear;
extern const float sTrigApproxSinCubic;
extern const float sTrigSinLinear;
extern const float sTrigSinCubic;
extern const float sTrigSinQuintic;
extern const float sTrigUnit;
extern const float sTrigCosQuadratic;
extern const float sTrigCosQuartic;
extern const float sTrigCosSextic;
extern const float sTrigPreciseSinLinear;
extern const float sTrigPreciseSinCubic;
extern const float sTrigPreciseSinQuintic;
extern const float sTrigPreciseSinSeptic;
extern const float sTrigPreciseCosQuadratic;
extern const float sTrigPreciseCosQuartic;
extern const float sTrigPreciseCosSextic;
extern const float sTrigPreciseCosOctic;
extern const double sTrigHighPrecisionAngleScale;
extern const double sTrigHighPrecisionSinCoeff1;
extern const double sTrigHighPrecisionSinCoeff3;
extern const double sTrigHighPrecisionSinCoeff5;
extern const double sTrigHighPrecisionSinCoeff7;
extern const double sTrigHighPrecisionSinCoeff9;
extern const double sTrigHighPrecisionSinCoeff11;
extern const double sTrigHighPrecisionCosCoeff0;
extern const double sTrigHighPrecisionCosCoeff2;
extern const double sTrigHighPrecisionCosCoeff4;
extern const double sTrigHighPrecisionCosCoeff6;
extern const double sTrigHighPrecisionCosCoeff8;
extern const double sTrigHighPrecisionCosCoeff10;
extern const double sTrigHighPrecisionCosCoeff12;

float fsin16Approx(u16 angle) {
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

float fsin16(u16 angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float x = fastCastS16ToFloat(&scaledAngleBits);
    float x2 = x * x;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return x * (x2 * (sTrigSinQuintic * x2 + sTrigSinCubic) + sTrigSinLinear);
    case 0x2000:
    case 0x4000:
        return (x2 * (x2 * (sTrigCosSextic * x2 + sTrigCosQuartic) + sTrigCosQuadratic) + sTrigUnit);
    case 0x6000:
    case 0x8000:
        return -(x * (x2 * (sTrigSinQuintic * x2 + sTrigSinCubic) + sTrigSinLinear));
    default:
        return -(x2 * (x2 * (sTrigCosSextic * x2 + sTrigCosQuartic) + sTrigCosQuadratic) + sTrigUnit);
    }
}

float fsin16Precise(u16 angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y * (y2 * (y2 * (sTrigPreciseSinSeptic * y2 + sTrigPreciseSinQuintic) + sTrigPreciseSinCubic) +
                    sTrigPreciseSinLinear);
    case 0x2000:
    case 0x4000:
        return y2 * (y2 * (y2 * (sTrigPreciseCosOctic * y2 + sTrigPreciseCosSextic) + sTrigPreciseCosQuartic) +
                     sTrigPreciseCosQuadratic) +
               sTrigUnit;
    case 0x6000:
    case 0x8000:
        return -(y * (y2 * (y2 * (sTrigPreciseSinSeptic * y2 + sTrigPreciseSinQuintic) + sTrigPreciseSinCubic) +
                      sTrigPreciseSinLinear));
    default:
        return -(y2 * (y2 * (y2 * (sTrigPreciseCosOctic * y2 + sTrigPreciseCosSextic) + sTrigPreciseCosQuartic) +
                       sTrigPreciseCosQuadratic) +
                 sTrigUnit);
    }
}

float fsin16HighPrecision(u16 angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float reducedFloat = fastCastS16ToFloat(&scaledAngleBits);
    double reducedAngle = sTrigHighPrecisionAngleScale * reducedFloat;
    double reducedSquared = reducedAngle * reducedAngle;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return (float)(reducedAngle *
                       (reducedSquared *
                            (reducedSquared *
                                 (reducedSquared * (reducedSquared * (sTrigHighPrecisionSinCoeff11 * reducedSquared +
                                                                      sTrigHighPrecisionSinCoeff9) +
                                                    sTrigHighPrecisionSinCoeff7) +
                                  sTrigHighPrecisionSinCoeff5) +
                             sTrigHighPrecisionSinCoeff3) +
                        sTrigHighPrecisionSinCoeff1));
    case 0x2000:
    case 0x4000:
        return (float)((
            reducedSquared *
                (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (sTrigHighPrecisionCosCoeff12 *
                                                                                             reducedSquared +
                                                                                         sTrigHighPrecisionCosCoeff10) +
                                                                       sTrigHighPrecisionCosCoeff8) +
                                                     sTrigHighPrecisionCosCoeff6) +
                                   sTrigHighPrecisionCosCoeff4) +
                 sTrigHighPrecisionCosCoeff2) +
            sTrigHighPrecisionCosCoeff0));
    case 0x6000:
    case 0x8000:
        return (float)(-(
            reducedAngle *
            (reducedSquared *
                 (reducedSquared * (reducedSquared * (reducedSquared * (sTrigHighPrecisionSinCoeff11 * reducedSquared +
                                                                        sTrigHighPrecisionSinCoeff9) +
                                                      sTrigHighPrecisionSinCoeff7) +
                                    sTrigHighPrecisionSinCoeff5) +
                  sTrigHighPrecisionSinCoeff3) +
             sTrigHighPrecisionSinCoeff1)));
    default:
        return (float)(-(
            reducedSquared *
                (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (sTrigHighPrecisionCosCoeff12 *
                                                                                             reducedSquared +
                                                                                         sTrigHighPrecisionCosCoeff10) +
                                                                       sTrigHighPrecisionCosCoeff8) +
                                                     sTrigHighPrecisionCosCoeff6) +
                                   sTrigHighPrecisionCosCoeff4) +
                 sTrigHighPrecisionCosCoeff2) +
            sTrigHighPrecisionCosCoeff0));
    }
}

float fcos16Approx(u16 angle) {
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

float fcos16(u16 angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y2 * (y2 * (sTrigCosSextic * y2 + sTrigCosQuartic) + sTrigCosQuadratic) + sTrigUnit;
    case 0x2000:
    case 0x4000:
        return -(y * (y2 * (sTrigSinQuintic * y2 + sTrigSinCubic) + sTrigSinLinear));
    case 0x6000:
    case 0x8000:
        return -(y2 * (y2 * (sTrigCosSextic * y2 + sTrigCosQuartic) + sTrigCosQuadratic) + sTrigUnit);
    default:
        return y * (y2 * (sTrigSinQuintic * y2 + sTrigSinCubic) + sTrigSinLinear);
    }
}

float fcos16Precise(u16 angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&scaledAngleBits);
    float y2 = y * y;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return y2 * (y2 * (y2 * (sTrigPreciseCosOctic * y2 + sTrigPreciseCosSextic) + sTrigPreciseCosQuartic) +
                     sTrigPreciseCosQuadratic) +
               sTrigUnit;
    case 0x2000:
    case 0x4000:
        return -(y * (y2 * (y2 * (sTrigPreciseSinSeptic * y2 + sTrigPreciseSinQuintic) + sTrigPreciseSinCubic) +
                      sTrigPreciseSinLinear));
    case 0x6000:
    case 0x8000:
        return -(y2 * (y2 * (y2 * (sTrigPreciseCosOctic * y2 + sTrigPreciseCosSextic) + sTrigPreciseCosQuartic) +
                       sTrigPreciseCosQuadratic) +
                 sTrigUnit);
    default:
        return y * (y2 * (y2 * (sTrigPreciseSinSeptic * y2 + sTrigPreciseSinQuintic) + sTrigPreciseSinCubic) +
                    sTrigPreciseSinLinear);
    }
}

float fcos16HighPrecision(u16 angle) {
    s16 scaledAngleBits = (s16)(int)((angle << 2) & 0x3FFFC);
    float reducedFloat = fastCastS16ToFloat(&scaledAngleBits);
    double reducedAngle = sTrigHighPrecisionAngleScale * reducedFloat;
    double reducedSquared = reducedAngle * reducedAngle;

    switch (angle & 0xE000) {
    case 0x0000:
    case 0xE000:
        return (float)((
            reducedSquared *
                (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (sTrigHighPrecisionCosCoeff12 *
                                                                                             reducedSquared +
                                                                                         sTrigHighPrecisionCosCoeff10) +
                                                                       sTrigHighPrecisionCosCoeff8) +
                                                     sTrigHighPrecisionCosCoeff6) +
                                   sTrigHighPrecisionCosCoeff4) +
                 sTrigHighPrecisionCosCoeff2) +
            sTrigHighPrecisionCosCoeff0));
    case 0x2000:
    case 0x4000:
        return (float)(-(
            reducedAngle *
            (reducedSquared *
                 (reducedSquared * (reducedSquared * (reducedSquared * (sTrigHighPrecisionSinCoeff11 * reducedSquared +
                                                                        sTrigHighPrecisionSinCoeff9) +
                                                      sTrigHighPrecisionSinCoeff7) +
                                    sTrigHighPrecisionSinCoeff5) +
                  sTrigHighPrecisionSinCoeff3) +
             sTrigHighPrecisionSinCoeff1)));
    case 0x6000:
    case 0x8000:
        return (float)(-(
            reducedSquared *
                (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (sTrigHighPrecisionCosCoeff12 *
                                                                                             reducedSquared +
                                                                                         sTrigHighPrecisionCosCoeff10) +
                                                                       sTrigHighPrecisionCosCoeff8) +
                                                     sTrigHighPrecisionCosCoeff6) +
                                   sTrigHighPrecisionCosCoeff4) +
                 sTrigHighPrecisionCosCoeff2) +
            sTrigHighPrecisionCosCoeff0));
    default:
        return (float)(reducedAngle *
                       (reducedSquared *
                            (reducedSquared *
                                 (reducedSquared * (reducedSquared * (sTrigHighPrecisionSinCoeff11 * reducedSquared +
                                                                      sTrigHighPrecisionSinCoeff9) +
                                                    sTrigHighPrecisionSinCoeff7) +
                                  sTrigHighPrecisionSinCoeff5) +
                             sTrigHighPrecisionSinCoeff3) +
                        sTrigHighPrecisionSinCoeff1));
    }
}

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
