#ifndef MAIN_DLL_FIREFLYLANTERN_H_
#define MAIN_DLL_FIREFLYLANTERN_H_

#include "main/game_object.h"
#include "ghidra_import.h"

void pinPon_updateEngaged(GameObject* obj, int* state);
void pinPon_init(GameObject* obj, void* state);
void fn_80154D0C(int obj, int state, u16* outAngle, float* outDistance);
u32 fireflyLanternSteerTowardTarget(short* obj, int state, u32 turnTime, f32 maxDistance);

#endif /* MAIN_DLL_FIREFLYLANTERN_H_ */
