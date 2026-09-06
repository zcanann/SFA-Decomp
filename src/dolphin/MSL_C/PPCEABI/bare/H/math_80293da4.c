#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/trig.h"
#include "main/math_80292d3c.h"

float mathSinfFast(float angle) {
    u16 quadrant;
    float reducedAngle;
    float reducedSquared;

    reducedAngle = trigReduceQuadrant(&quadrant, angle);
    quadrant += (*(u32*)&angle & 0x80000000) >> 29;
    reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return reducedAngle * (-0.07768012f * reducedSquared + 0.7846358f);
        case 2:
            return reducedSquared * (0.015371595f * reducedSquared + -0.30824488f) + 0.99999f;
        case 4:
            return -(reducedAngle * (-0.07768012f * reducedSquared + 0.7846358f));
        default:
            return -(reducedSquared * (0.015371595f * reducedSquared + -0.30824488f) + 0.99999f);
    }
}

float mathSinf(float angle) {
    u16 quadrant;
    float reducedAngle;
    float reducedSquared;

    reducedAngle = trigReduceQuadrant(&quadrant, angle);
    quadrant += (*(u32*)&angle & 0x80000000) >> 29;
    reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return reducedAngle * (reducedSquared * (0.0024270867f * reducedSquared + -0.08071397f) + 0.78539425f);
        case 2:
            return reducedSquared * (reducedSquared * (-0.000318879f * reducedSquared + 0.015849913f) + -0.30842426f) + 1.0f;
        case 4:
            return -(reducedAngle * (reducedSquared * (0.0024270867f * reducedSquared + -0.08071397f) + 0.78539425f));
        default:
            return -(reducedSquared * (reducedSquared * (-0.000318879f * reducedSquared + 0.015849913f) + -0.30842426f) + 1.0f);
    }
}

float mathSinfPrecise(float angle) {
    u16 quadrant;
    float reducedAngle;
    float reducedSquared;

    reducedAngle = trigReduceQuadrant(&quadrant, angle);
    quadrant += (*(u32*)&angle & 0x80000000) >> 29;
    reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return reducedAngle * (reducedSquared * (reducedSquared * (-3.58772e-05f * reducedSquared + 0.002489872f) + -0.0807454f) + 0.7853982f);
        case 2:
            return reducedSquared * (reducedSquared * (reducedSquared * (3.5298042e-06f * reducedSquared + -0.0003259386f) + 0.015854325f) + -0.30842513f) + 1.0f;
        case 4:
            return -(reducedAngle * (reducedSquared * (reducedSquared * (-3.58772e-05f * reducedSquared + 0.002489872f) + -0.0807454f) + 0.7853982f));
        default:
            return -(reducedSquared * (reducedSquared * (reducedSquared * (3.5298042e-06f * reducedSquared + -0.0003259386f) + 0.015854325f) + -0.30842513f) + 1.0f);
    }
}

float mathSinfHighPrecision(float angle) {
    int quadrant;
    double reducedAngle;
    double reducedSquared;

    reducedAngle = trigReduceQuadrantHighPrecision(&quadrant, angle);
    quadrant += (*(u32*)&angle & 0x80000000) >> 29;
    reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return (float)(reducedAngle * (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (-2.473889883359452e-08 * reducedSquared + 2.7554973093759717e-06) + -0.00019841261464659544) + 0.008333333318980809) + -0.16666666666563978) + 0.9999999999999805));
        case 2:
            return (float)(reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (2.048770813211803e-09 * reducedSquared + -2.755268200651971e-07) + 2.4801561642773723e-05) + -0.001388888881954176) + 0.041666666665824886) + -0.4999999999999672) + 1.0);
        case 4:
            return (float)(-(reducedAngle * (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (-2.473889883359452e-08 * reducedSquared + 2.7554973093759717e-06) + -0.00019841261464659544) + 0.008333333318980809) + -0.16666666666563978) + 0.9999999999999805)));
        default:
            return (float)(-(reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (2.048770813211803e-09 * reducedSquared + -2.755268200651971e-07) + 2.4801561642773723e-05) + -0.001388888881954176) + 0.041666666665824886) + -0.4999999999999672) + 1.0));
    }
}

float mathCosf(float angle) {
    u16 quadrant;
    float reducedAngle = trigReduceQuadrant(&quadrant, angle);
    float reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return reducedSquared * (reducedSquared * (-0.000318879f * reducedSquared + 0.015849913f) + -0.30842426f) + 1.0f;
        case 2:
            return -(reducedAngle * (reducedSquared * (0.0024270867f * reducedSquared + -0.08071397f) + 0.78539425f));
        case 4:
            return -(reducedSquared * (reducedSquared * (-0.000318879f * reducedSquared + 0.015849913f) + -0.30842426f) + 1.0f);
        default:
            return reducedAngle * (reducedSquared * (0.0024270867f * reducedSquared + -0.08071397f) + 0.78539425f);
    }
}

float mathCosfPrecise(float angle) {
    u16 quadrant;
    float reducedAngle = trigReduceQuadrant(&quadrant, angle);
    float reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return reducedSquared * (reducedSquared * (reducedSquared * (3.5298042e-06f * reducedSquared + -0.0003259386f) + 0.015854325f) + -0.30842513f) + 1.0f;
        case 2:
            return -(reducedAngle * (reducedSquared * (reducedSquared * (-3.58772e-05f * reducedSquared + 0.002489872f) + -0.0807454f) + 0.7853982f));
        case 4:
            return -(reducedSquared * (reducedSquared * (reducedSquared * (3.5298042e-06f * reducedSquared + -0.0003259386f) + 0.015854325f) + -0.30842513f) + 1.0f);
        default:
            return reducedAngle * (reducedSquared * (reducedSquared * (-3.58772e-05f * reducedSquared + 0.002489872f) + -0.0807454f) + 0.7853982f);
    }
}

float mathCosfHighPrecision(float angle) {
    int quadrant;
    double reducedAngle = trigReduceQuadrantHighPrecision(&quadrant, angle);
    double reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return (float)(reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (2.048770813211803e-09 * reducedSquared + -2.755268200651971e-07) + 2.4801561642773723e-05) + -0.001388888881954176) + 0.041666666665824886) + -0.4999999999999672) + 1.0);
        case 2:
            return (float)(-(reducedAngle * (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (-2.473889883359452e-08 * reducedSquared + 2.7554973093759717e-06) + -0.00019841261464659544) + 0.008333333318980809) + -0.16666666666563978) + 0.9999999999999805)));
        case 4:
            return (float)(-(reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (2.048770813211803e-09 * reducedSquared + -2.755268200651971e-07) + 2.4801561642773723e-05) + -0.001388888881954176) + 0.041666666665824886) + -0.4999999999999672) + 1.0));
        default:
            return (float)(reducedAngle * (reducedSquared * (reducedSquared * (reducedSquared * (reducedSquared * (-2.473889883359452e-08 * reducedSquared + 2.7554973093759717e-06) + -0.00019841261464659544) + 0.008333333318980809) + -0.16666666666563978) + 0.9999999999999805));
    }
}
