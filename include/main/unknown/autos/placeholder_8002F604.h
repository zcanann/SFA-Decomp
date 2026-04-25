#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8002F604_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8002F604_H_

#include "ghidra_import.h"

undefined2 ObjAnim_GetPrimaryEventCountdown(int objAnim);
void ObjAnim_WriteStateWord(int objAnim,int stateIndex,short wordIndex,int value);
void ObjAnim_SetPrimaryEventStepFrames(int objAnim,uint frameCount);
undefined4 ObjAnim_SampleRootCurvePhase(double distance,int objAnim,float *phaseOut);
undefined4 ObjAnim_AdvanceCurrentMove(double moveStepScale,double deltaTime);
undefined4 ObjAnim_SetMoveProgress(double moveProgress,int objAnim);
void ObjAnim_SetCurrentMove(double moveProgress,double param_2,double param_3,undefined8 param_4,
                            undefined8 param_5,undefined8 param_6,undefined8 param_7,
                            undefined8 param_8,undefined4 param_9,undefined4 param_10,u32 flags,
                            undefined4 param_12,undefined4 param_13,undefined4 param_14,
                            undefined4 param_15,undefined4 param_16);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8002F604_H_ */
