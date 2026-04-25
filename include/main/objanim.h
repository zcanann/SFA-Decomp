#ifndef MAIN_OBJANIM_H_
#define MAIN_OBJANIM_H_

#include "ghidra_import.h"

typedef struct ObjAnimDef ObjAnimDef;
typedef struct ObjAnimState ObjAnimState;

void ObjAnim_SetBlendMove(int objAnim,ObjAnimDef *animDef,ObjAnimState *state,uint moveId,s16 eventState);
void Object_ObjAnimSetPrimaryBlendMove(int objAnim,uint moveId,int eventState);
void Object_ObjAnimSetSecondaryBlendMove(int objAnim,uint moveId,int eventState);
undefined4 Object_ObjAnimAdvanceMove(double moveStepScale,double deltaTime,int objAnim,int events);
undefined4 Object_ObjAnimSetMoveProgress(double moveProgress,int objAnim);
undefined4 Object_ObjAnimSetMove(double moveProgress,int objAnim,uint moveId,undefined flags);

#endif /* MAIN_OBJANIM_H_ */
