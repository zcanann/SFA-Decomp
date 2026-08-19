#ifndef MAIN_DLL_FIREFLYLANTERN_H_
#define MAIN_DLL_FIREFLYLANTERN_H_

#include "game/objects/object.h"
#include "types.h"
#include "main/dll/duster_api.h"

void pinPon_updateEngaged(GameObject* obj, int* state);
void pinPon_init(GameObject* obj, void* state);
void fireflyLanternGetTargetAngleAndDistance(GameObject* obj, void* state, u16* outAngle, float* outDistance);
u32 fireflyLanternSteerTowardTarget(short* obj, void* state, u32 turnTime, f32 maxDistance);
#endif /* MAIN_DLL_FIREFLYLANTERN_H_ */
