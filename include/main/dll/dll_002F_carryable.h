#ifndef MAIN_DLL_DLL_002F_CARRYABLE_H_
#define MAIN_DLL_DLL_002F_CARRYABLE_H_

#include "main/game_object.h"

void objSaveFn_800ea774(GameObject* obj);
void Carryable_initialise(void);
void Carryable_release(void);
void Carryable_init(GameObject* obj, void* state, int arg2);
int Carryable_updateHeld(GameObject* obj, void* state);
int Carryable_updateRenderState(GameObject* obj, int flag);
void Carryable_free(GameObject* obj);
s32 Carryable_getCarryState(void* state);
s32 Carryable_wasJustGrabbed(void* state);
u8 Carryable_getSurfaceType(void* state);
void Carryable_setGravityEnabled(void* state, u8 clear);
void Carryable_setDropDisabled(void* state, u8 enable);
s32 Carryable_getDropDisabled(void* state);
void Carryable_setSuppressPositionSave(void* state, u8 enable);
void Carryable_stopCarrying(GameObject* obj, void* state);

#endif /* MAIN_DLL_DLL_002F_CARRYABLE_H_ */
