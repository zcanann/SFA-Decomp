#ifndef MAIN_DLL_STAFFACTION_H_
#define MAIN_DLL_STAFFACTION_H_

#include "ghidra_import.h"

undefined4 fn_801659B8(s16 *obj,u32 *params);
undefined4
FUN_801659b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
undefined4
FUN_80165e74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
void fn_80165B3C(int obj,int state);
void FUN_801660c0(int param_1,int param_2);
void FUN_801661ec(short *param_1,int param_2);
void fn_80166444(int obj,int state);
void FUN_8016693c(int param_1,int param_2);
void fn_80166840(int obj,int state,float *hit,float *end);
void FUN_80166c6c(int param_1,int param_2,float *param_3,float *param_4);
void updateConstrainedChaseVelocity(int obj,float targetX,float targetY,float targetZ,float blend);
void FUN_80166e9c(double param_1,double param_2,double param_3,double param_4,int param_5);
void FUN_8016716c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void dll_D3_render(int obj,int p2,int p3,int p4,int p5,s8 visible);
void FUN_8016725c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);

#endif /* MAIN_DLL_STAFFACTION_H_ */
