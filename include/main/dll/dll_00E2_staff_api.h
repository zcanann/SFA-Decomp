#ifndef MAIN_DLL_DLL_00E2_STAFF_API_H_
#define MAIN_DLL_DLL_00E2_STAFF_API_H_

#include "main/game_object.h"

void objSetAnimField48to0(GameObject* obj);
void staff_addHitReactValue(int* obj, s32 delta);
void staffDoGrowShrinkAnim(GameObject* obj, u8 grow, u8 alternateRate, int unused);
void staff_func10(int* obj, s32 value);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_setHitReactValue(int* obj, s32 value);
void staff_startSwipe(int* obj, s16 index, f32 arg2, f32 arg3);
void superQuakeFn_8016d9fc(f32* position);

#endif /* MAIN_DLL_DLL_00E2_STAFF_API_H_ */
