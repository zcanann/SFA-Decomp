#ifndef MAIN_DLL_DLL_000F_UNK_H_
#define MAIN_DLL_DLL_000F_UNK_H_

#include "types.h"
#include "main/player_control_interface.h"
#include "game/objects/object.h"
#include "main/dll/baddie_state.h"

typedef int (*PlayerSubstateFn)(GameObject* obj, BaddieState* state, f32 dt);
typedef int (*PlayerStateFn)(GameObject* obj, BaddieState* state, f32 dt);
typedef BaddieStateExitFn PlayerStateExitFn;

void player_moveTowardPoint(GameObject* obj, BaddieState* state, f32 px, f32 pz, f32 lo, f32 hi, f32 spd);
void player_followCurve(GameObject* obj, BaddieState* state, f32 cx, f32 cz, f32 t, int unused);
void player_applyVelocityStep(GameObject* obj, BaddieState* state, f32 t);
void player_steerFromInput(GameObject* obj, BaddieState* state);
void player_updateParticles(GameObject* obj, BaddieState* unused, int effectId, int count, int mode);
void player_doProjGfx(GameObject* obj, BaddieState* unusedA, int resIdBase, int count, int unusedB, int mode);
void player_updateSecondaryBlend(GameObject* obj, BaddieState* state, int moveA, int moveB);
void player_setAnimIds(GameObject* unusedObj, BaddieState* unusedState, u32 a, u32 b);
void player_clearXZvel(GameObject* obj, BaddieState* state);
void PlayerControl_ApplyDirectionalVelocity(GameObject* obj, BaddieState* state, f32 t, f32 scale, int angle);
void dll_0F_func19_nop(void);
void player_updateCurve(GameObject* obj, BaddieState* state, f32 t);
void player_findCurve(GameObject* obj, BaddieState* state, int curveId);
void player_playSoundFn10(GameObject* obj, BaddieState* state, int bit, int idx, int* sfxTable);
void player_playSoundFn0F(GameObject* obj, BaddieState* state, int bit, int idx, int* sfxTable);
void player_rotateTowardEnemy(GameObject* obj, BaddieState* state, f32 unusedTimeDelta, int spd);
void PlayerControl_ApplyYawNudge(GameObject* obj, BaddieState* state, f32 f1, f32 f2);
void PlayerControl_ApplyPositionNudge(GameObject* obj, BaddieState* state, f32 f1, f32 f2);
void PlayerControl_UpdateTurnFromRootMotion(GameObject* obj, BaddieState* state, f32 f1, f32 f2, f32 f3);
void player_advanceMove(GameObject* obj, BaddieState* state, f32 dt, int flags);
void player_runSubstateMachine(GameObject* obj, BaddieState* state, f32 dt, PlayerSubstateFn* stateFns);
void playerRunStateMachine(GameObject* obj, BaddieState* state, f32 dt, PlayerStateFn* stateFns);
void player_setState(GameObject* obj, BaddieState* state, int new_state);
void player_setOverride(GameObject* obj);
void player_updateVel(GameObject* obj, BaddieState* state, void* stateFns);
void player_update(GameObject* obj, BaddieState* state, float dt, float pathDt, void* stateFns, void* auxStateFns);
void player_init(GameObject* unused, BaddieState* state, int a, int b);
void player_release(void);
void player_initialise(void);

#endif /* MAIN_DLL_DLL_000F_UNK_H_ */
