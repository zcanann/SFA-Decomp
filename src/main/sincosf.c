#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

/* Address-based reads retain these named constants without duplicate literals. */
const float gSinCosZero = 0.0f;
const float gSinCosSinCoeff1 = 0.78539425f;
const float gSinCosSinCoeff3 = -0.08071397f;
const float gSinCosSinCoeff5 = 0.0024270867f;
const float gSinCosCosCoeff0 = 1.0f;
const float gSinCosCosCoeff2 = -0.30842426f;
const float gSinCosCosCoeff4 = 0.015849913f;
const float gSinCosCosCoeff6 = -0.000318879f;


void mathSinCosf(float angle, float* outSin, float* outCos) {
    u16 quadrant;
    float reducedAngle = trigReduceQuadrant(&quadrant, angle);
    float reducedSquared = reducedAngle * reducedAngle;
    float sinApprox =
        reducedAngle * (reducedSquared * (*(const float*)&gSinCosSinCoeff5 * reducedSquared + *(const float*)&gSinCosSinCoeff3) + *(const float*)&gSinCosSinCoeff1);
    float cosApprox =
        reducedSquared * (reducedSquared * (*(const float*)&gSinCosCosCoeff6 * reducedSquared + *(const float*)&gSinCosCosCoeff4) + *(const float*)&gSinCosCosCoeff2) +
        *(const float*)&gSinCosCosCoeff0;

    switch (quadrant & 6) {
    case 0:
        if (!(angle >= *(const float*)&gSinCosZero)) {
            sinApprox = -sinApprox;
        }
        *outSin = sinApprox;
        *outCos = cosApprox;
        break;
    case 2:
        if (!(angle >= *(const float*)&gSinCosZero)) {
            cosApprox = -cosApprox;
        }
        *outSin = cosApprox;
        *outCos = -sinApprox;
        break;
    case 4:
        if (angle >= *(const float*)&gSinCosZero) {
            sinApprox = -sinApprox;
        }
        *outSin = sinApprox;
        *outCos = -cosApprox;
        break;
    default:
        if (angle >= *(const float*)&gSinCosZero) {
            cosApprox = -cosApprox;
        }
        *outSin = cosApprox;
        *outCos = sinApprox;
        break;
    }
}
