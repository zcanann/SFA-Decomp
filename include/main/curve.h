#ifndef MAIN_CURVE_H_
#define MAIN_CURVE_H_

#include "global.h"
#include "main/curve_types.h"

typedef struct CurveHeapNode {
    u16 priority;
    u16 value;
} CurveHeapNode;

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
extern f32 lbl_803DE664;
extern f32 lbl_803DE668;
extern f32 lbl_803DE66C;
extern f32 lbl_803DE680;

extern char sCurvesSetupMoveNetworkCurveTooFewControlPoints[];
extern char sCurvesSetupMoveNetworkCurveBadControlPointCount[];
extern char sCurvesMoveTooFewControlPoints[];
extern char sCurvesMoveBadControlPointCount[];

#endif /* MAIN_CURVE_H_ */
