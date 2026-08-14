#ifndef MAIN_DLL_PLAYER_H_
#define MAIN_DLL_PLAYER_H_

#include "game/objects/object_fwd.h"
#include "global.h"

struct PlayerState;

int playerUpdateAirborneMotion(GameObject* obj, struct PlayerState* inner, struct PlayerState* state);
void playerUpdate(GameObject* obj);
void playerProcessMessages(GameObject* obj, int inner, int state);
void playerProcessHitResponse(GameObject* obj, struct PlayerState* inner, struct PlayerState* state);
void playerDoHitDetection(GameObject* obj);
int playerCheckCommonTransitions(GameObject* obj, struct PlayerState* state, struct PlayerState* inner, f32 fv);

int playerCheckIfClimbingOntoWall(int obj, int state, int state2, void* out, f32 fv, u32 mask);
int playerStateMoving(int obj, int state, f32 fv);
int playerStateOnLadder(GameObject* obj, struct PlayerState* state);
int playerStateClimbWall(GameObject* obj, struct PlayerState* state);
int playerStateAimStaff(GameObject* obj, struct PlayerState* state, f32 fv);
int playerStateAttack(GameObject* obj, struct PlayerState* state, f32 fv);
int playerState1D(int obj, struct PlayerState* state, f32 fv);
int playerStateIdle(GameObject* obj, struct PlayerState* state, f32 fv);
int playerState08(GameObject* obj, struct PlayerState* state, f32 fv);

#endif
