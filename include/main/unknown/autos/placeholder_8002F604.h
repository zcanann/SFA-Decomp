#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8002F604_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8002F604_H_

#include "ghidra_import.h"

undefined2 ObjAnim_GetPrimaryEventCountdown(int objAnim);
void ObjAnim_WriteStateWord(int objAnim,int stateIndex,short wordIndex,int value);
void ObjAnim_SetPrimaryEventStepFrames(int objAnim,uint frameCount);
undefined4 ObjAnim_SampleRootCurvePhase(double distance,int objAnim,float *phaseOut);
undefined4 ObjAnim_AdvanceCurrentMove(double moveStepScale,double deltaTime,int objAnim,float *events);
undefined4 ObjAnim_SetMoveProgress(f32 moveProgress,int objAnim);
undefined4 ObjAnim_SetCurrentMove(double moveProgress,int objAnim,int moveId,u32 flags);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8002F604_H_ */
