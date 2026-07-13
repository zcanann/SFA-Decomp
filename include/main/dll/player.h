#ifndef MAIN_DLL_PLAYER_H_
#define MAIN_DLL_PLAYER_H_

#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objfx.h"
#include "main/screen_transition.h"
#include "main/dll/player_80295318_shared.h"
#include "main/dll/player_api.h"
#include "main/dll/player_state.h"

int fn_802AD2F4(GameObject* obj, int inner, int state);
void playerItemGetAnimFn(int obj, int inner, int state);
void fn_802AFB0C(int obj, int inner, int state);
void playerDoHitDetection(int obj);
int fn_802AC7DC(int obj, int state, int inner, f32 fv);

s8 playerCheckIfClimbingOntoWall(int obj, int state, int state2, void* out, f32 fv, u32 mask);
int playerStateMoving(int obj, int state);
int playerStateOnLadder(int obj, int state);
int playerStateClimbWall(GameObject* obj, int state);
int playerStateAimStaff(int obj, int state);
int playerStateAttack(GameObject* obj, int state, f32 fv);
int playerState1D(int obj, int state, f32 fv);
int playerStateIdle(int obj, int state, f32 fv);
int playerState08(GameObject* obj, int state, f32 fv);

int objFn_802962b4(GameObject* obj);

#endif
