#ifndef MAIN_DLL_DLL_002F_CARRYABLE_H_
#define MAIN_DLL_DLL_002F_CARRYABLE_H_

#include "main/game_object.h"

void objSaveFn_800ea774(GameObject* obj);
void Carryable_initialise(void);
void Carryable_release(void);
void Carryable_init(GameObject* obj, int state);
int Carryable_updateHeld(u8* obj);
int Carryable_updateRenderState(int* obj, int flag);
void Carryable_free(int obj);
s32 Carryable_getCarryState(u8* state);
s32 Carryable_wasJustGrabbed(u8* state);
u8 Carryable_getSurfaceType(u8* state);
void Carryable_setGravityEnabled(u8* state, u8 clear);
void Carryable_setDropDisabled(u8* state, u8 enable);
s32 Carryable_getDropDisabled(u8* state);
void Carryable_setSuppressPositionSave(u8* state, u8 enable);
void Carryable_stopCarrying(int* obj, u8* param2);

#endif /* MAIN_DLL_DLL_002F_CARRYABLE_H_ */
