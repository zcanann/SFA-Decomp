#ifndef SFA_PRACTICE_H
#define SFA_PRACTICE_H

#ifdef SFA_PRACTICE
#include "types.h"
#include "game/objects/object.h"
#include "main/dll/player_state.h"

void Practice_SetArenaLo(void* start);
void Practice_PadUpdate(void);
void Practice_Draw(void);
void Practice_PlayerControls(GameObject* obj, PlayerState* state, f32 dt);
void Practice_SurfaceResponse(GameObject* obj, PlayerState* state, PlayerState* cfg, f32 dt);
#endif

#endif
