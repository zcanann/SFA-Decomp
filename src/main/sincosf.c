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
    /* Seed the two polynomial accumulators with x and x squared. */
    float sine = trigReduceQuadrant(&quadrant, angle);
    float cosine = sine * sine;
    sine =
        sine *
        (cosine * (*(const float*)&gSinCosSinCoeff5 * cosine + *(const float*)&gSinCosSinCoeff3) +
         *(const float*)&gSinCosSinCoeff1);
    cosine =
        cosine *
            (cosine * (*(const float*)&gSinCosCosCoeff6 * cosine + *(const float*)&gSinCosCosCoeff4) +
             *(const float*)&gSinCosCosCoeff2) +
        *(const float*)&gSinCosCosCoeff0;

    switch (quadrant & 6) {
    case 0:
        if (!(angle >= *(const float*)&gSinCosZero)) {
            sine = -sine;
        }
        *outSin = sine;
        *outCos = cosine;
        break;
    case 2:
        if (!(angle >= *(const float*)&gSinCosZero)) {
            cosine = -cosine;
        }
        *outSin = cosine;
        *outCos = -sine;
        break;
    case 4:
        if (angle >= *(const float*)&gSinCosZero) {
            sine = -sine;
        }
        *outSin = sine;
        *outCos = -cosine;
        break;
    default:
        if (angle >= *(const float*)&gSinCosZero) {
            cosine = -cosine;
        }
        *outSin = cosine;
        *outCos = sine;
        break;
    }
}
