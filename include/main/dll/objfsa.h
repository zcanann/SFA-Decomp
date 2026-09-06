#ifndef MAIN_DLL_OBJFSA_H_
#define MAIN_DLL_OBJFSA_H_

struct GameObject;
struct RomCurveDef;

#include "types.h"
#include "main/curve.h"
#include "main/dll/curve_walker.h"
#include "main/dll/objfsa_query_api.h"

int RomCurve_setClosed(RomCurveWalker *state,int closed);
u8 RomCurve_goNextPoint(RomCurveWalker *state);
void RomCurve_stepClamped(RomCurveWalker *state,f32 step);
int RomCurve_advanceToNextSegment(RomCurveWalker *state, struct RomCurveDef *targetCurve);
int RomCurve_setupHermiteSegment(RomCurveWalker *state, struct RomCurveDef *fromCurve,
                                struct RomCurveDef *toCurve, struct RomCurveDef *targetCurve);
int curves_findNearObj(struct GameObject* obj,int *curveTypes,int typeCount,int action,int bboxMode);
f32 curves_getPathLength(struct RomCurveDef *a, struct RomCurveDef *b, f32 *posA, f32 *posB, f32 t1, f32 t2);
void curves_getPos(struct RomCurveDef* curve,float *outX,float *outY,float *outZ,f32 phase);
struct RomCurveDef* RomCurve_findProjectedCurveFromStart(struct RomCurveDef* curve, f32 x, f32 y, f32 z, f32* outPhase);
struct RomCurveDef* Objfsa_FindNearestCurveType24(f32* position, int walkGroupFilter, int curveSubtypeFilter);
struct RomCurveDef* Objfsa_FindNearestEnabledCurveType24(f32* position, int walkGroupFilter, int curveSubtypeFilter);

#endif /* MAIN_DLL_OBJFSA_H_ */
