#ifndef MAIN_PLAYER_EYE_ANIM_H_
#define MAIN_PLAYER_EYE_ANIM_H_

#include "main/game_object.h"

typedef struct PlayerBlinkState PlayerBlinkState;

void playerEyeAnimFn_80038988(GameObject* obj, PlayerBlinkState* blinkState, u32 flags);

#endif /* MAIN_PLAYER_EYE_ANIM_H_ */
