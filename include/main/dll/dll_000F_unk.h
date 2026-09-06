#ifndef MAIN_DLL_DLL_000F_UNK_H_
#define MAIN_DLL_DLL_000F_UNK_H_

#include "types.h"
#include "game/objects/object.h"
#include "main/dll/baddie_state.h"

typedef int (*PlayerSubstateFn)(GameObject* obj, BaddieState* state, f32 dt);
typedef int (*PlayerStateFn)(GameObject* obj, BaddieState* state, f32 dt);
typedef BaddieStateExitFn PlayerStateExitFn;

typedef struct PlayerMoveBuf
{
    f32 a;
    f32 b;
    f32 c;
    u8 pad_0C[2];
    s16 angleDelta;
    u8 pad_10[2];
    u8 flag;
    s8 ids[8];
    s8 count;
} PlayerMoveBuf;

void player_moveTowardPoint(GameObject* obj, BaddieState* state, f32 px, f32 pz, f32 lo, f32 hi, f32 spd);
void player_followCurve(GameObject* obj, BaddieState* state, f32 cx, f32 cz, f32 t, int unused);
void player_applyVelocityStep(GameObject* obj, BaddieState* state, f32 t);
void player_steerFromInput(GameObject* obj, BaddieState* state);
void player_updateParticles(GameObject* obj, int unused, int effectId, int count, int mode);
void player_doProjGfx(GameObject* obj, int unusedA, int resIdBase, int count, int unusedB, int mode);
void player_updateSecondaryBlend(GameObject* obj, BaddieState* state, int moveA, int moveB);
void player_setAnimIds(int unused1, int unused2, u32 a, u32 b);
void player_clearXZvel(GameObject* obj, BaddieState* state);
void dll_0F_func13(GameObject* obj, BaddieState* state, int angle, f32 t, f32 scale);
void dll_0F_func19_nop(void);
void player_updateCurve(GameObject* obj, BaddieState* state, f32 t);
void player_findCurve(GameObject* obj, BaddieState* state, int curveId);
void player_playSoundFn10(GameObject* obj, BaddieState* state, int bit, int idx, int* sfxTable);
void player_playSoundFn0F(GameObject* obj, BaddieState* state, int bit, int idx, int* sfxTable);
void player_rotateTowardEnemy(GameObject* obj, BaddieState* state, int spd);
void player_render2(GameObject* obj, BaddieState* state, f32 f1, f32 f2);
void player_modelMtxFn(f32* mtx, BaddieState* state, f32 f1, f32 f2);
void dll_0F_func0B(GameObject* obj, BaddieState* state, f32 f1, f32 f2, f32 f3);
void player_advanceMove(short* moveState, BaddieState* state, f32 dt, int flags);
void player_runSubstateMachine(GameObject* obj, BaddieState* state, f32 dt, PlayerSubstateFn* stateFns);
void playerRunStateMachine(GameObject* obj, BaddieState* state, f32 dt, PlayerStateFn* stateFns);
void player_setState(GameObject* obj, BaddieState* state, int new_state);
void player_setOverride(u32 x);
void player_updateVel(GameObject* obj, BaddieState* state, void* stateFns);
void player_update(GameObject* obj, BaddieState* state, float dt, float pathDt, void* stateFns, void* auxStateFns);
void player_init(void* unused, BaddieState* state, int a, int b);
void player_release(void);
void player_initialise(void);

#endif /* MAIN_DLL_DLL_000F_UNK_H_ */
