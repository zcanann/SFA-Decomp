#ifndef MAIN_DLL_OBJFSA_H_
#define MAIN_DLL_OBJFSA_H_

#include "ghidra_import.h"
#include "main/curve.h"
#include "main/dll/curve_walker.h"
#include "main/dll/objfsa_query_api.h"

#define OBJFSA_PATCHGROUP_PATCH_COUNT 4

struct ObjfsaWalkGroupPatchInfo
{
    u8 walkGroupIndex;
    u8 patchMask;
    u16 patchGroupIds[OBJFSA_PATCHGROUP_PATCH_COUNT];
};

void FUN_800d9878(u64 param_1,u64 param_2,u32 param_3,u32 param_4,
                 int param_5,int param_6);
void FUN_800d98fc(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11);
u32
FUN_800d9de0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,
            float *param_9,float param_10,u32 param_11,u32 param_12,
            u32 param_13,u32 param_14,u32 param_15,u32 param_16);
bool FUN_800da5e8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 float *param_9,float param_10,float param_11,float param_12,u32 param_13,
                 u32 param_14,u32 param_15,u32 param_16);
u16
FUN_800db110(float *param_1,int param_2,u32 param_3,u32 param_4,u8 param_5);
u32
FUN_800dd3e4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,
            float *param_9,u32 param_10,u32 param_11);
u32
FUN_800dd62c(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,
            float *param_9,u32 param_10,u32 param_11,int param_12,int param_13,
            u32 param_14,u32 param_15,u32 param_16);
int RomCurve_setClosed(RomCurveWalker *state,int closed);
u8 RomCurve_goNextPoint(RomCurveWalker *state);
void RomCurve_stepClamped(RomCurveWalker *state,f32 step);
int curveFn_800da23c(RomCurveWalker *state,void *targetCurve);
int RomCurve_setupHermiteSegment(RomCurveWalker *state,void *fromCurve,void *toCurve,void *targetCurve);
u32
FUN_800ddf84(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,
            float *param_9,float param_10,u32 param_11,u32 param_12,
            u32 param_13,u32 param_14,u32 param_15,u32 param_16);
u32
FUN_800ddf8c(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,
            float *param_9);
u32
FUN_800de998(double param_1,u64 param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,float *param_9,int param_10,
            u32 param_11,int param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
int curves_findNearObj(int obj,int *curveTypes,int typeCount,int action,char bboxMode);
f32 curves_getPathLength(u32 a, u32 b, f32 *posA, f32 *posB, f32 t1, f32 t2);
void curves_getPos(int curve,float *outX,float *outY,float *outZ,f32 phase);
int RomCurve_findProjectedCurveFromStart(int curve, f32 x, f32 y, f32 z, f32* outPhase);
void* Objfsa_FindNearestCurveType24(f32* position, int walkGroupFilter, int curveSubtypeFilter);
void* Objfsa_FindNearestEnabledCurveType24(f32* position, int walkGroupFilter, int curveSubtypeFilter);

#endif /* MAIN_DLL_OBJFSA_H_ */
