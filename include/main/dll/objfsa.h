#ifndef MAIN_DLL_OBJFSA_H_
#define MAIN_DLL_OBJFSA_H_

#include "ghidra_import.h"
#include "main/dll/curve_walker.h"

void player_setScale(short *moveState, u32 *obj, f32 dt, int flags);
void FUN_800d9090(double param_1,double param_2,short *param_3,int param_4);
void FUN_800d90f8(double param_1,double param_2,double param_3,short *param_4,int param_5);
void FUN_800d91b0(double param_1,short *param_2,u32 *param_3,u32 param_4);
void FUN_800d9384(u32 param_1,u32 param_2,int param_3);
void FUN_800d94f0(u32 param_1,u32 param_2,int param_3);
void FUN_800d97d4(int param_1,int param_2,int param_3);
void FUN_800d9874(int param_1,u32 *param_2,int param_3);
void FUN_800d9878(u64 param_1,u64 param_2,u32 param_3,u32 param_4,
                 int param_5,int param_6);
void FUN_800d987c(u32 param_1,int param_2,u16 param_3,u16 param_4);
void FUN_800d98fc(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11);
void FUN_800d9a30(void);
void FUN_800d9a64(void);
void FUN_800d9a98(float *param_1);
u32 FUN_800d9b7c(int param_1,int param_2);
u32
FUN_800d9de0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,
            float *param_9,float param_10,u32 param_11,u32 param_12,
            u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_800da594(double param_1,float *param_2);
bool FUN_800da5e8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 float *param_9,float param_10,float param_11,float param_12,u32 param_13,
                 u32 param_14,u32 param_15,u32 param_16);
int FUN_800da5f0(float *param_1,u32 param_2,int param_3);
void FUN_800da700(u32 param_1,u32 param_2,int param_3);
void FUN_800da850(u32 param_1,u8 *param_2);
void FUN_800da860(u32 param_1,u32 param_2,u32 param_3);
void FUN_800daa04(u32 param_1,u32 param_2,int param_3);
u32 FUN_800daf38(float *param_1,u32 param_2,u32 param_3);
u16
FUN_800db110(float *param_1,int param_2,u32 param_3,u32 param_4,u8 param_5);
u32 FUN_800db2f0(float *param_1);
void FUN_800db47c(float *param_1,u8 *param_2);
u16 FUN_800db690(float *param_1);
int FUN_800db820(float *param_1);
void FUN_800dbc68(void);
void FUN_800dd3dc(void);
void FUN_800dd3e0(void);
u32
FUN_800dd3e4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,
            float *param_9,u32 param_10,u32 param_11);
int FUN_800dd3ec(int param_1,int param_2,u32 param_3);
int FUN_800dd50c(int param_1,int param_2,u32 param_3);
u32
FUN_800dd62c(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,
            float *param_9,u32 param_10,u32 param_11,int param_12,int param_13,
            u32 param_14,u32 param_15,u32 param_16);
void FUN_800dde2c(int param_1,int param_2);
int RomCurve_setClosed(RomCurveWalker *state,int closed);
u8 RomCurve_goNextPoint(RomCurveWalker *state);
int Curve_AdvanceAlongPath(RomCurveWalker *state,f32 step);
void RomCurve_stepClamped(RomCurveWalker *state,f32 step);
int curveFn_800da23c(RomCurveWalker *state,void *targetCurve);
int fn_800DA980(RomCurveWalker *state,void *fromCurve,void *toCurve,void *targetCurve);
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
void FUN_800dece0(void);
int FUN_800df2a4(double param_1,double param_2,double param_3,int param_4,int param_5);
u32 FUN_800df46c(u64 param_1,double param_2,double param_3);
f32 curves_lengthFn24(u32 a, u32 b, f32 *posA, f32 *posB, f32 t1, f32 t2);
void curves_getPos(int curve,float *outX,float *outY,float *outZ,f32 phase);
int RomCurve_findProjectedCurveFromStart(int curve,f32 x,f32 y,f32 z,float *outPhase);

#endif /* MAIN_DLL_OBJFSA_H_ */
