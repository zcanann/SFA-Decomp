#ifndef MAIN_DLL_DLL_0158_GUNPOWDERBARREL_H_
#define MAIN_DLL_DLL_0158_GUNPOWDERBARREL_H_

#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/gunpowderbarrel_state.h"
#include "main/dll/player_motion.h"
#include "main/objlib.h"
#include "main/vecmath.h"

void gunpowderbarrel_setPlayerHeldState(int* obj, u8 heldByPlayer);
void gunpowderbarrel_homeOnTarget(int* obj, s16 a, s16 b);
void gunpowderbarrel_launchAtTarget(int obj, u8 flag);

#endif
