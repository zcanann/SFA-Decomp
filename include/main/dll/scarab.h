#ifndef MAIN_DLL_SCARAB_H_
#define MAIN_DLL_SCARAB_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/object_descriptor.h"

void iceBaddie_update(GameObject* param_1, int param_2, int param_3);
void dll_CE_func0B(GameObject* obj, int v);
void IceBall_update(u16* param_1, int param_2);

int grimble_stateHandlerB05(int* obj, GroundBaddieState* state);
int grimble_stateHandlerB04(int* obj, GroundBaddieState* state);
int grimble_stateHandlerB03(int obj, GroundBaddieState* state);
int grimble_stateHandlerB01(int* obj, GroundBaddieState* state);
int grimble_stateHandlerB00(int obj, GroundBaddieState* state);
int grimble_stateHandlerA09(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerA08(int* obj, GroundBaddieState* state);
int grimble_stateHandlerA07(short* obj, GroundBaddieState* state);
int grimble_stateHandlerA06(GameObject* obj, GroundBaddieState* state, f32 speed);
int grimble_stateHandlerA05(short* obj, GroundBaddieState* state);
int grimble_stateHandlerA04(short* obj, GroundBaddieState* state);
int grimble_stateHandlerA03(short* obj, GroundBaddieState* state);
int scarab_updateProximityGate(int* obj, GroundBaddieState* state);

extern ObjectDescriptor11WithPadding gChukChukObjDescriptor;
extern ObjectDescriptor gIceBallObjDescriptor;

#endif /* MAIN_DLL_SCARAB_H_ */
