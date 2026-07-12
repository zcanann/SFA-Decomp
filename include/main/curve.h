#ifndef MAIN_CURVE_H_
#define MAIN_CURVE_H_

#include "global.h"
#include "main/curve_eval.h"

#ifndef MAIN_CURVE_TYPES_DEFINED
#define MAIN_CURVE_TYPES_DEFINED

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

typedef struct CurveHeapNode {
    u16 priority;
    u16 value;
} CurveHeapNode;

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
void Curve_SampleSegmentPoints(f32* px, f32* py, f32* pz, f32* outX, f32* outY, f32* outZ, int count,
                               CurveCoeffFn coeffFn);
void Curve_BuildSegmentLengthTable(Curve* curve, int count);
void curvesSetupMoveNetworkCurve(Curve* curve);
void curvesMove(Curve *curve);
void CurveHeap_SiftDown(CurveHeapNode* heap, s32 count, s32 index);

extern f32 gCurveSegmentCount;
extern f32 gCurveForwardDiffStep;
extern int gCurveCachedSampleCount;
extern f32 gCurveForwardDiffCoeffs[];

extern f32 lbl_803DE658;
extern f32 lbl_803DE674;
extern f32 lbl_803DE67C;
extern f32 lbl_803DE660;
extern f32 lbl_803DE680;

extern char sCurvesSetupMoveNetworkCurveTooFewControlPoints[];
extern char sCurvesSetupMoveNetworkCurveBadControlPointCount[];
extern char sCurvesMoveTooFewControlPoints[];
extern char sCurvesMoveBadControlPointCount[];

#endif /* MAIN_CURVE_H_ */
