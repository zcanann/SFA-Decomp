#ifndef MAIN_OBJANIM_H_
#define MAIN_OBJANIM_H_

#include "ghidra_import.h"

typedef struct ObjAnimDef ObjAnimDef;
typedef struct ObjAnimState ObjAnimState;
typedef struct ObjAnimComponent ObjAnimComponent;
typedef struct ObjAnimEventList ObjAnimEventList;

void ObjAnim_SetBlendMove(ObjAnimComponent *objAnim,ObjAnimDef *animDef,ObjAnimState *state,
                          uint moveId,int eventState);
void Object_ObjAnimSetPrimaryBlendMove(ObjAnimComponent *objAnim,uint moveId,int eventState);
void Object_ObjAnimSetSecondaryBlendMove(ObjAnimComponent *objAnim,uint moveId,int eventState);
undefined4 Object_ObjAnimAdvanceMove(f32 moveStepScale,f32 deltaTime,int objAnim,int events);
undefined4 Object_ObjAnimSetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim);
undefined4 Object_ObjAnimSetMove(f32 moveProgress,int objAnim,int moveId,int flags);
undefined2 ObjAnim_GetCurrentEventCountdown(ObjAnimComponent *objAnim);
void ObjAnim_WriteStateWord(ObjAnimComponent *objAnim,int stateIndex,short wordIndex,int value);
void ObjAnim_SetCurrentEventStepFrames(ObjAnimComponent *objAnim,uint frameCount);
undefined4 ObjAnim_SampleRootCurvePhase(double distance,int objAnim,float *phaseOut);
undefined4 ObjAnim_AdvanceCurrentMove(double moveStepScale,double deltaTime,int objAnim,
                                      ObjAnimEventList *events);
undefined4 ObjAnim_SetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim);
undefined4 ObjAnim_SetCurrentMove(double moveProgress,int objAnim,int moveId,u32 flags);

#endif /* MAIN_OBJANIM_H_ */
