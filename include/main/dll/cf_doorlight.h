#ifndef MAIN_DLL_DLL_131_H_
#define MAIN_DLL_DLL_131_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/dll/baddie_state.h"

int kaldachom_stateHandlerB05(int obj, int state);
int kaldachom_stateHandlerB04(int obj, GroundBaddieState* state);
int kaldachom_stateHandlerB03(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerB02(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerB01(int* obj, GroundBaddieState* state);
int kaldachom_stateHandlerB00(int* obj, GroundBaddieState* state);
int kaldachom_stateHandlerA07(GameObject* obj, int state);

#endif /* MAIN_DLL_DLL_131_H_ */
