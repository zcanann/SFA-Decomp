#ifndef MAIN_DLL_DLL_002F_CARRYABLE_H_
#define MAIN_DLL_DLL_002F_CARRYABLE_H_

#include "game/objects/object.h"
#include "main/carryable_state.h"

void Carryable_putDownAndSavePos(GameObject* obj);
void Carryable_initialise(void);
void Carryable_release(void);
void Carryable_init(GameObject* obj, CarryableState* state, int arg2);
int Carryable_updateHeld(GameObject* obj, CarryableState* state);
int Carryable_updateRenderState(GameObject* obj, int flag);
void Carryable_free(GameObject* obj);
s32 Carryable_getCarryState(CarryableState* state);
s32 Carryable_wasJustGrabbed(CarryableState* state);
u8 Carryable_getSurfaceType(CarryableState* state);
void Carryable_setGravityEnabled(CarryableState* state, u8 clear);
void Carryable_setDropDisabled(CarryableState* state, u8 enable);
s32 Carryable_getDropDisabled(CarryableState* state);
void Carryable_setSuppressPositionSave(CarryableState* state, u8 enable);
void Carryable_stopCarrying(GameObject* obj, CarryableState* state);

#endif /* MAIN_DLL_DLL_002F_CARRYABLE_H_ */
