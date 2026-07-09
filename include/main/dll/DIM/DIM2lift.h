#ifndef MAIN_DLL_DIM_DIM2LIFT_H_
#define MAIN_DLL_DIM_DIM2LIFT_H_

#include "global.h"
#include "main/dll/DIM/dll_01E0_dimboss.h"

int DIMbossAnim_updatePlayerHitReaction(int obj, int state);
int DIMbossAnim_finishDefeat(int obj, int state);
int DIMbossAnim_hasMoveDone(int unused, int *state);
int DIMbossAnim_returnToIdleWhenDone(int obj, int state);
int DIMbossAnim_selectTargetControlMode(int *obj);

int DIMbossHitDetect_tonsilSlam(int obj, int state);
int DIMbossHitDetect_liftSlam(int obj, int state);
int DIMbossHitDetect_liftImpact(int obj, int state);
int DIMbossHitDetect_chooseIdleTaunt(int obj, int state);
int DIMbossHitDetect_lungeAttack(int obj, int state, f32 weight);
int DIMbossHitDetect_breathBurst(int obj, int state, f32 weight);
int DIMbossHitDetect_blueWhiteCapture(int obj, int state, f32 weight);
int DIMbossHitDetect_blueWhiteEventCapture(int obj, int state, f32 weight);
int DIMbossHitDetect_randomSwipe(int obj, int state, f32 weight);
int DIMbossHitDetect_trackTargetMove(int obj, int state, f32 weight);
int DIMbossHitDetect_applyForwardMove(int *obj, u8 *state, f32 weight);
int DIMbossHitDetect_resetIdleMove(int *obj, u8 *state);

void DIM2icicle_spawnBlueWhiteEffect(DIMbossEffectMarker *source, f32 *velocity);
void DIM2icicle_createStateLight(struct GameObject *obj, u8 isGreen);

#endif /* MAIN_DLL_DIM_DIM2LIFT_H_ */
