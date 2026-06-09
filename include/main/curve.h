#ifndef MAIN_CURVE_H_
#define MAIN_CURVE_H_

#include "global.h"

#ifndef MAIN_CURVE_TYPES_DEFINED
#define MAIN_CURVE_TYPES_DEFINED

typedef f32 (*CurveEvalFn)(f32 t, f32 *values, f32 *outTangent);
typedef void (*CurveCoeffFn)(f32 *values, f32 *coeffs);

typedef struct Curve {
    f32 t;
    f32 segmentDistance;
    f32 pathDistance;
    f32 pathLength;
    int idx;
    f32 totalLen;
    f32 segLen[20];
    f32 sample[3];
    f32 tangent[3];
    int dir;
    f32 *px;
    f32 *py;
    f32 *pz;
    int count;
    CurveEvalFn eval;
    CurveCoeffFn coeffFn;
} Curve;

#endif /* MAIN_CURVE_TYPES_DEFINED */

STATIC_ASSERT(sizeof(Curve) == 0x9C);
STATIC_ASSERT(offsetof(Curve, pathDistance) == 0x08);
STATIC_ASSERT(offsetof(Curve, pathLength) == 0x0C);
STATIC_ASSERT(offsetof(Curve, sample) == 0x68);
STATIC_ASSERT(offsetof(Curve, dir) == 0x80);
STATIC_ASSERT(offsetof(Curve, px) == 0x84);
STATIC_ASSERT(offsetof(Curve, count) == 0x90);
STATIC_ASSERT(offsetof(Curve, eval) == 0x94);
STATIC_ASSERT(offsetof(Curve, coeffFn) == 0x98);

int Curve_AdvanceAlongPath(Curve *curve, f32 dt);
void curvesMove(Curve *curve);
f32 Curve_EvalHermite(f32 t, f32 *values, f32 *outTangent);
f32 Curve_EvalBSpline(f32 t, f32 *values, f32 *outTangent);
void Curve_BuildBSplineCoeffs(f32 *values, f32 *coefficients);

#endif /* MAIN_CURVE_H_ */
