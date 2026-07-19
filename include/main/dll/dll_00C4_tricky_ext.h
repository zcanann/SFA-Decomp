#ifndef MAIN_DLL_DLL_00C4_TRICKY_EXT_H_
#define MAIN_DLL_DLL_00C4_TRICKY_EXT_H_

#include "main/game_object.h"

u8 baddie_canSeeTarget(GameObject* obj, int state, void* from, void* to);
void baddie_updateSightQuadrants(int obj, int state, f32 radius);

#endif /* MAIN_DLL_DLL_00C4_TRICKY_EXT_H_ */
