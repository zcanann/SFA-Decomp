#ifndef MAIN_DLL_PLAYER_MOTION_API_H_
#define MAIN_DLL_PLAYER_MOTION_API_H_

#include "global.h"
#include "main/game_object.h"

void fn_802B0EA4(GameObject* obj, int motionState, int baddieState);
void fn_802B1B28(GameObject* obj, f32 timeDelta);
void fn_802B1BF8(GameObject* obj, int motionState, int baddieState, f32 unusedTimeDelta);

#endif /* MAIN_DLL_PLAYER_MOTION_API_H_ */
