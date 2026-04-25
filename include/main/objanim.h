#ifndef MAIN_OBJANIM_H_
#define MAIN_OBJANIM_H_

#include "ghidra_import.h"

void ObjAnim_SetBlendMove(int objAnim,int animDef,int state,uint moveId,s16 eventState);
void Object_ObjAnimSetPrimaryBlendMove(int objAnim,uint moveId,s16 eventState);
void Object_ObjAnimSetSecondaryBlendMove(int objAnim,uint moveId,s16 eventState);
undefined4 Object_ObjAnimAdvanceMove(double moveStepScale,double deltaTime,int objAnim,int events);
undefined4 Object_ObjAnimSetMoveProgress(double moveProgress,int objAnim);
undefined4 Object_ObjAnimSetMove(double moveProgress,double param_2,double param_3,undefined8 param_4,
                                 undefined8 param_5,undefined8 param_6,undefined8 param_7,
                                 undefined8 param_8,int objAnim,uint moveId,undefined flags);

#endif /* MAIN_OBJANIM_H_ */
