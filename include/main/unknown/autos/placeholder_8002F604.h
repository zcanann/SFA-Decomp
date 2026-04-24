#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8002F604_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8002F604_H_

#include "ghidra_import.h"

#define ObjAnim_GetPrimaryEventCountdown FUN_8002f5d4
#define ObjAnim_WriteStateWord FUN_8002f5f4
#define ObjAnim_SetPrimaryEventStepFrames FUN_8002f638
#define ObjAnim_SampleRootCurvePhase FUN_8002f6ac
#define ObjAnim_AdvanceCurrentMove FUN_8002fc3c
#define ObjAnim_SetMoveProgress FUN_800305c4
#define ObjAnim_SetCurrentMove FUN_800305f8

undefined2 FUN_8002f5d4(int param_1);
void FUN_8002f5f4(int param_1,int param_2,short param_3,undefined2 param_4);
void FUN_8002f638(int param_1,uint param_2);
undefined4 FUN_8002f6ac(double param_1,int param_2,float *param_3);
undefined4 FUN_8002fc3c(double param_1,double param_2);
undefined4 FUN_800305c4(double param_1,int param_2);
void FUN_800305f8(double param_1,double param_2,double param_3,undefined8 param_4,
                  undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                  undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                  undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8002F604_H_ */
