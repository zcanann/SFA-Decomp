#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

extern const float gSinCosSinCoeff1;
extern const float gSinCosSinCoeff3;
extern const float gSinCosSinCoeff5;
extern const float gSinCosZero;
extern const float gSinCosCosCoeff0;
extern const float gSinCosCosCoeff2;
extern const float gSinCosCosCoeff4;
extern const float gSinCosCosCoeff6;

void mathSinCosf(float angle, float* outSin, float* outCos) {
    u16 quadrant;
    float reducedAngle = trigReduceQuadrant(&quadrant, angle);
    float reducedSquared = reducedAngle * reducedAngle;
    float sinApprox =
        reducedAngle * (reducedSquared * (gSinCosSinCoeff5 * reducedSquared + gSinCosSinCoeff3) + gSinCosSinCoeff1);
    float cosApprox =
        reducedSquared * (reducedSquared * (gSinCosCosCoeff6 * reducedSquared + gSinCosCosCoeff4) + gSinCosCosCoeff2) +
        gSinCosCosCoeff0;

    switch (quadrant & 6) {
    case 0:
        sinApprox = angle >= gSinCosZero ? sinApprox : -sinApprox;
        *outSin = sinApprox;
        *outCos = cosApprox;
        break;
    case 2:
        cosApprox = angle >= gSinCosZero ? cosApprox : -cosApprox;
        *outSin = cosApprox;
        *outCos = -sinApprox;
        break;
    case 4:
        if (angle >= gSinCosZero) {
            sinApprox = -sinApprox;
        }
        *outSin = sinApprox;
        *outCos = -cosApprox;
        break;
    default:
        if (angle >= gSinCosZero) {
            cosApprox = -cosApprox;
        }
        *outSin = cosApprox;
        *outCos = sinApprox;
        break;
    }
}

const float gSinCosZero = 0.0f;
const float gSinCosSinCoeff1 = 0.78539425f;
const float gSinCosSinCoeff3 = -0.08071397f;
const float gSinCosSinCoeff5 = 0.0024270867f;
const float gSinCosCosCoeff0 = 1.0f;
const float gSinCosCosCoeff2 = -0.30842426f;
const float gSinCosCosCoeff4 = 0.015849913f;
const float gSinCosCosCoeff6 = -0.000318879f;
