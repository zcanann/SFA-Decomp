#ifndef MAIN_OBJANIM_H_
#define MAIN_OBJANIM_H_

#include "global.h"

typedef struct ModelFileHeader ObjAnimDef;
typedef struct ObjModel ObjAnimBank;
typedef struct ObjAnimState ObjAnimState;
typedef struct ObjAnimComponent ObjAnimComponent;
typedef struct ObjAnimEventTable ObjAnimEventTable;
typedef struct ObjAnimEventList ObjAnimEventList;
typedef struct ObjWeaponDaTable ObjWeaponDaTable;

typedef void (*ObjAnimSequenceFreeCallback)(void *ctx,u8 *obj);
typedef int (*ObjAnimSequenceConditionCallback)(void *ctx,u8 *obj);
extern char gObjAnimMissingCachedMoveWarning[];

#define OBJANIM_STATE_INDEX_CURRENT 0
#define OBJANIM_STATE_INDEX_ACTIVE 1
#define OBJANIM_STATE_WORD_EVENT_COUNTDOWN 0
#define OBJANIM_STATE_WORD_EVENT_STATE 1
#define OBJANIM_STATE_WORD_PREV_EVENT_STATE 2


void ObjAnim_SetBlendMove(ObjAnimComponent *objAnim,ObjAnimDef *animDef,ObjAnimState *state,
                          u32 moveId,int eventState);
void Object_ObjAnimSetPrimaryBlendMove(ObjAnimComponent *objAnim,u32 moveId,int eventState);
void Object_ObjAnimSetSecondaryBlendMove(ObjAnimComponent *objAnim,u32 moveId,int eventState);
/* ABI-facing callbacks pass object pointers through void*; implementations cast to ObjAnimComponent. */
int Object_ObjAnimAdvanceMove(void *objAnimHandle,f32 moveStepScale,f32 deltaTime,
                              ObjAnimEventList *events);
int Object_ObjAnimSetMoveProgress(ObjAnimComponent *objAnim,f32 moveProgress);
int Object_ObjAnimSetMove(void *objAnimHandle,int moveId,f32 moveProgress,u8 moveControlFlags);
int ObjAnim_GetCurrentEventCountdown(ObjAnimComponent *objAnim);
void ObjAnim_WriteStateWord(ObjAnimComponent *objAnim,int stateIndex,short wordIndex,int value);
void ObjAnim_SetCurrentEventStepFrames(ObjAnimComponent *objAnim,u32 frameCount);
int ObjAnim_SampleRootCurvePhase(ObjAnimComponent *objAnim,f32 distance,float *phaseOut);
int ObjAnim_AdvanceCurrentMove(void* objAnimHandle, f32 moveStepScale, f32 deltaTime, ObjAnimEventList* events);
int ObjAnim_SetMoveProgress(ObjAnimComponent *objAnim,f32 moveProgress);
int ObjAnim_SetCurrentMove(void *objAnimHandle,int moveId,f32 moveProgress,u8 moveControlFlags);
void *ObjAnim_LoadCachedMove(int animId,int moveIndex,u8 *cache,ObjAnimDef *animDef);
void objGetWeaponDa(u8 *objAnim,int objType,ObjWeaponDaTable *weaponDaTable,int key,u8 load);
void ObjAnim_LoadMoveEvents(u8 *objAnim,int objType,ObjAnimEventTable *eventTable,u32 moveId,
                            u8 load);

#endif /* MAIN_OBJANIM_H_ */
