#ifndef MAIN_DLL_DLL_80161130_H_
#define MAIN_DLL_DLL_80161130_H_

#include "main/dll/baddie_state.h"
#include "main/game_object.h"

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

#endif /* MAIN_DLL_DLL_80161130_H_ */
