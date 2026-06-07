#ifndef MAIN_OBJANIM_H_
#define MAIN_OBJANIM_H_

#include "ghidra_import.h"

typedef struct ObjAnimDef ObjAnimDef;
typedef struct ObjAnimState ObjAnimState;
typedef struct ObjAnimComponent ObjAnimComponent;
typedef struct ObjAnimEventTable ObjAnimEventTable;
typedef struct ObjAnimEventList ObjAnimEventList;
typedef struct ObjWeaponDaTable ObjWeaponDaTable;

typedef int (*ObjAnimSetProgressObjectFirstFn)(int objAnimHandle,f32 progress);
typedef int (*ObjAnimSampleRootCurveObjectFirstFn)(int objAnimHandle,f32 distance,
                                                   float *phaseOut);
typedef int (*ObjAnimSetCurrentMoveObjectFirstFn)(int objAnimHandle,int moveId,f32 moveProgress,
                                                  int moveControlFlags);
typedef int (*ObjAnimAdvanceObjectFirstFn)(int objAnimHandle,double moveStepScale,double deltaTime,
                                           ObjAnimEventList *events);
typedef int (*ObjAnimAdvanceObjectFirstF32Fn)(int objAnimHandle,f32 moveStepScale,f32 deltaTime,
                                              ObjAnimEventList *events);

extern char gObjAnimSetBlendMoveMissingAnimWarning[];

#define OBJANIM_STATE_INDEX_CURRENT 0
#define OBJANIM_STATE_INDEX_ACTIVE 1
#define OBJANIM_STATE_WORD_EVENT_COUNTDOWN 0
#define OBJANIM_STATE_WORD_EVENT_STATE 1
#define OBJANIM_STATE_WORD_PREV_EVENT_STATE 2

void ObjAnim_SetBlendMove(ObjAnimComponent *objAnim,ObjAnimDef *animDef,ObjAnimState *state,
                          uint moveId,s16 eventState);
void Object_ObjAnimSetPrimaryBlendMove(ObjAnimComponent *objAnim,uint moveId,int eventState);
void Object_ObjAnimSetSecondaryBlendMove(ObjAnimComponent *objAnim,uint moveId,int eventState);
/* ABI-facing callbacks pass object pointers through int; implementations cast to ObjAnimComponent. */
int Object_ObjAnimAdvanceMove(f32 moveStepScale,f32 deltaTime,int objAnimHandle,
                              ObjAnimEventList *events);
int Object_ObjAnimSetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim);
int Object_ObjAnimSetMove(f32 moveProgress,int objAnimHandle,int moveId,int moveControlFlags);
u16 ObjAnim_GetCurrentEventCountdown(ObjAnimComponent *objAnim);
void ObjAnim_WriteStateWord(ObjAnimComponent *objAnim,int stateIndex,short wordIndex,int value);
void ObjAnim_SetCurrentEventStepFrames(ObjAnimComponent *objAnim,uint frameCount);
int ObjAnim_SampleRootCurvePhase(f32 distance,ObjAnimComponent *objAnim,float *phaseOut);
int ObjAnim_AdvanceCurrentMove(f32 moveStepScale,f32 deltaTime,int objAnimHandle,
                               ObjAnimEventList *events);
int ObjAnim_SetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim);
int ObjAnim_SetCurrentMove(int objAnimHandle,int moveId,f32 moveProgress,int moveControlFlags);
void *ObjAnim_LoadCachedMove(int animId,int moveIndex,u8 *cache,ObjAnimDef *animDef);
void objGetWeaponDa(u8 *objAnim,int objType,ObjWeaponDaTable *weaponDaTable,int key,u8 load);
void ObjAnim_LoadMoveEvents(u8 *objAnim,int objType,ObjAnimEventTable *eventTable,u32 moveId,
                            u8 load);

#endif /* MAIN_OBJANIM_H_ */
