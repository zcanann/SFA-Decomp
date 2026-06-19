#ifndef MAIN_DLL_PLAYER_H_
#define MAIN_DLL_PLAYER_H_

#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objfx.h"
#include "main/screen_transition.h"
#include "main/dll/player_80295318_shared.h"
#include "main/dll/player_state.h"

int fn_802AD2F4(int obj, int inner, int state);
void fn_802B249C(int obj, int inner, int state);
void fn_802AFB0C(int obj, int inner, int state);
void playerDoHitDetection(int obj);

#endif
