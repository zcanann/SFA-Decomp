#ifndef MAIN_DLL_DIM_DIM2LIFT_H_
#define MAIN_DLL_DIM_DIM2LIFT_H_

#include "main/game_object.h"
#include "global.h"
#include "main/dll/DIM/dll_01E0_dimboss.h"

typedef struct Dim2BossMoveChoices
{
    s16 surprised[6]; /* 0x00: random far-approach reaction, picked 0..5 */
    s16 group3[8];    /* 0x0C: hitPoints==3 round-robin */
    s16 group2[8];    /* 0x1C: hitPoints==2 round-robin */
    s16 group1[8];    /* 0x2C: hitPoints==1 round-robin */
} Dim2BossMoveChoices;

STATIC_ASSERT(offsetof(Dim2BossMoveChoices, group3) == 0x0C);
STATIC_ASSERT(offsetof(Dim2BossMoveChoices, group2) == 0x1C);
STATIC_ASSERT(offsetof(Dim2BossMoveChoices, group1) == 0x2C);
STATIC_ASSERT(sizeof(Dim2BossMoveChoices) == 0x3C);

extern Dim2BossMoveChoices gDim2LiftFarMoveChoices;

int DIMbossAnim_updatePlayerHitReaction(GameObject* obj, int state);
int DIMbossAnim_finishDefeat(GameObject* obj, int state);
int DIMbossAnim_hasMoveDone(int unused, int* state);
int DIMbossAnim_returnToIdleWhenDone(int obj, int state);
int DIMbossAnim_selectTargetControlMode(int* obj);

int DIMbossHitDetect_tonsilSlam(GameObject* obj, int state);
int DIMbossHitDetect_liftSlam(GameObject* obj, int state);
int DIMbossHitDetect_liftImpact(int obj, int state);
int DIMbossHitDetect_chooseIdleTaunt(GameObject* obj, int state);
int DIMbossHitDetect_lungeAttack(GameObject* obj, int state, f32 weight);
int DIMbossHitDetect_breathBurst(GameObject* obj, int state, f32 weight);
int DIMbossHitDetect_blueWhiteCapture(GameObject* obj, int state, f32 weight);
int DIMbossHitDetect_blueWhiteEventCapture(GameObject* obj, int state, f32 weight);
int DIMbossHitDetect_randomSwipe(GameObject* obj, int state, f32 weight);
int DIMbossHitDetect_trackTargetMove(GameObject* obj, int state, f32 weight);
int DIMbossHitDetect_applyForwardMove(int* obj, u8* state, f32 weight);
int DIMbossHitDetect_resetIdleMove(int* obj, u8* state);

void DIM2icicle_spawnBlueWhiteEffect(DIMbossEffectMarker* source, f32* velocity);
void DIM2icicle_createStateLight(GameObject* obj, u8 isGreen);

#endif /* MAIN_DLL_DIM_DIM2LIFT_H_ */
