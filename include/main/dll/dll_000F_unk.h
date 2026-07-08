#ifndef MAIN_DLL_DLL_000F_UNK_H_
#define MAIN_DLL_DLL_000F_UNK_H_

#include "types.h"

struct PartDesc
{
    s16 ang[3];
    f32 sc[4];
};

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

void player_moveTowardPoint(int* a, int* ctx, f32 px, f32 pz, f32 lo, f32 hi, f32 spd);
void player_followCurve(int* obj, int* state, f32 cx, f32 cz, f32 t, int unused);
void player_applyVelocityStep(int* p, int* ctx, f32 t);
void fn_800D8414(int* obj, int* ctx);
void player_updateParticles(int* obj, int unused, int effectId, int count, int mode);
void player_doProjGfx(int* obj, int unusedA, int resIdBase, int count, int unusedB, int mode);
void player_updateSecondaryBlend(int* obj, int* ctx, int moveA, int moveB);
void player_setAnimIds(int unused1, int unused2, u32 a, u32 b);
void player_clearXZvel(int* obj, int* state);
void dll_0F_func13(s16* obj, int* state, int angle, f32 t, f32 scale);
void dll_0F_func19_nop(void);
void player_updateCurve(int* obj, int* state, f32 t);
void player_findCurve(int* obj, int* state, int curveId);
void player_playSoundFn10(int* obj, int* state, int bit, int idx, int* sfxTable);
void player_playSoundFn0F(int* obj, int* state, int bit, int idx, int* sfxTable);
void player_rotateTowardEnemy(int* obj, int* ctx, int spd);
void player_render2(s16* obj, int* state, f32 f1, f32 f2);
void player_modelMtxFn(f32* mtx, int* state, f32 f1, f32 f2);
void dll_0F_func0B(int* obj, int* state, f32 f1, f32 f2, f32 f3);
void player_advanceMove(short* moveState, u32* obj, f32 dt, int flags);
void fn_800D915C(int p1, int* obj, f32 fval, void* fnTable);
void playerRunStateMachine(char* pos, char* state, float dt, int stateFns);
void player_setState(void* ctx, void* p, int new_state);
void player_setOverride(u32 x);
void player_updateVel(char* p, char* obj, int unused);
void player_update(char* pos, char* state, float dt, float pathDt, int stateFns, int auxStateFns);
void player_init(int unused, void* obj, int a, int b);
void player_release(void);
void player_initialise(void);

#endif /* MAIN_DLL_DLL_000F_UNK_H_ */
