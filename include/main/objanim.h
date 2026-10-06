#ifndef MAIN_OBJANIM_H_
#define MAIN_OBJANIM_H_

#include "global.h"
#include "game/objects/object_fwd.h"

typedef struct ModelFileHeader ObjAnimDef;
typedef struct ObjModel ObjAnimBank;
typedef struct ObjAnimState ObjAnimState;
typedef struct ObjAnimCachedMove ObjAnimCachedMove;
typedef struct ObjAnimComponent ObjAnimComponent;
typedef struct ObjAnimEventTable ObjAnimEventTable;
typedef struct ObjAnimEventList ObjAnimEventList;
typedef struct ObjWeaponDaTable ObjWeaponDaTable;

typedef void (*ObjAnimSequenceFreeCallback)(void* ctx, u8* obj);
typedef int (*ObjAnimSequenceConditionCallback)(void* ctx, u8* obj, int conditionOpcode);
extern char gObjAnimMissingCachedMoveWarning[];

#define OBJANIM_STATE_INDEX_CURRENT         0
#define OBJANIM_STATE_INDEX_ACTIVE          1
#define OBJANIM_STATE_WORD_EVENT_COUNTDOWN  0
#define OBJANIM_STATE_WORD_EVENT_STATE      1
#define OBJANIM_STATE_WORD_PREV_EVENT_STATE 2

void ObjAnim_SetBlendMove(GameObject* obj, ObjAnimDef* animDef, ObjAnimState* state, u32 moveId, int eventState);
void ObjAnim_SetLayeredBlendMove(GameObject* obj, u32 moveId, int eventState);
void ObjAnim_SetCurrentBlendMove(GameObject* obj, u32 moveId, int eventState);
int ObjAnim_AdvanceLayeredMove(GameObject* obj, f32 moveStepScale, f32 deltaTime, ObjAnimEventList* events);
int ObjAnim_SetLayeredMoveProgress(GameObject* obj, f32 moveProgress);
int ObjAnim_SetLayeredMove(GameObject* obj, int moveId, f32 moveProgress, u8 moveControlFlags);
int ObjAnim_GetCurrentEventCountdown(GameObject* obj);
void ObjAnim_WriteStateWord(GameObject* obj, int stateIndex, short wordIndex, int value);
void ObjAnim_SetCurrentEventStepFrames(GameObject* obj, u32 frameCount);
int ObjAnim_SampleRootCurvePhase(GameObject* obj, f32 distance, float* phaseOut);
/* Returns nonzero when updated progress is >= 1 or < 0, before wrapping or clamping. */
int ObjAnim_AdvanceCurrentMove(GameObject* obj, f32 moveStepScale, f32 deltaTime, ObjAnimEventList* events);
int ObjAnim_SetMoveProgress(GameObject* obj, f32 moveProgress);
int ObjAnim_SetCurrentMove(GameObject* obj, int moveId, f32 moveProgress, u8 moveControlFlags);
void* ObjAnim_LoadCachedMove(int animId, int moveIndex, ObjAnimCachedMove* cache, ObjAnimDef* animDef);
void objGetWeaponDa(GameObject* obj, int objType, ObjWeaponDaTable* weaponDaTable, int key, u8 load);
void ObjAnim_LoadMoveEvents(GameObject* obj, int objType, ObjAnimEventTable* eventTable, u32 moveId, u8 load);

#endif /* MAIN_OBJANIM_H_ */
