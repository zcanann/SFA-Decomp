#ifndef MAIN_CURVE_TYPES_H_
#define MAIN_CURVE_TYPES_H_

#include "global.h"
#include "main/curve_eval.h"

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

STATIC_ASSERT(sizeof(Curve) == 0x9C);
STATIC_ASSERT(offsetof(Curve, pathDistance) == 0x08);
STATIC_ASSERT(offsetof(Curve, pathLength) == 0x0C);
STATIC_ASSERT(offsetof(Curve, sample) == 0x68);
STATIC_ASSERT(offsetof(Curve, dir) == 0x80);
STATIC_ASSERT(offsetof(Curve, px) == 0x84);
STATIC_ASSERT(offsetof(Curve, count) == 0x90);
STATIC_ASSERT(offsetof(Curve, eval) == 0x94);
STATIC_ASSERT(offsetof(Curve, coeffFn) == 0x98);

#endif /* MAIN_CURVE_TYPES_H_ */
