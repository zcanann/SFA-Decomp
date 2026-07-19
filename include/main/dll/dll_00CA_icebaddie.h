#ifndef MAIN_DLL_ICEBADDIE_H_
#define MAIN_DLL_ICEBADDIE_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"

/*
 * dll_00CA (icebaddie, ex-"mediumbasket") is cut/unused content (see the .c file header for
 * the full story). The only externally-referenced symbols are these whirlpool
 * grouping helpers, which are SHARED engine utilities: the generic enemy DLL
 * (dll_00C9) calls them for water/whirlpool objects.
 */
void iceBaddie_enterWhirlpoolGroup(GameObject* obj, GroundBaddieState* state);
void iceBaddie_leaveWhirlpoolGroup(GameObject* obj, GroundBaddieState* state);

void iceBaddie_updateEffectAnchors(GameObject* obj, int state);
void iceBaddie_update(GameObject* obj, int unusedA, int unusedB);
int iceBaddie_updateOpenHitState(GameObject* obj, int state);
int iceBaddie_updateOpenState(GameObject* obj, int state);
int iceBaddie_updateHideResetState(GameObject* obj, int state);
int iceBaddie_updateImpactHitState(GameObject* obj, int state);
int iceBaddie_updateSpinState(GameObject* obj, int state);
int iceBaddie_stateHandlerA05(GameObject* obj, int state);
int iceBaddie_stateHandlerA06(GameObject* obj, int state);
int iceBaddie_updateHeightBlendState(GameObject* obj, int state);
int iceBaddie_updateControlMove5State(int* obj, GroundBaddieState* state);
int iceBaddie_updateCommDownState(GameObject* obj, int state);
int iceBaddie_updateDropState(GameObject* obj, int state);
int iceBaddie_stateHandlerA0B(GameObject* obj, int state);
int iceBaddie_updateContactHitState(GameObject* obj, int state);
int iceBaddie_updateLandingState(GameObject* obj, int state);
int iceBaddie_checkTargetState(int obj, int state);
int iceBaddie_stateHandlerB01(int* obj, GroundBaddieState* state);
int iceBaddie_stateHandlerB02(GameObject* obj, int state);
int iceBaddie_stateHandlerB03(GameObject* obj, int state);
int iceBaddie_stateHandlerB04(int obj, int state);
int iceBaddie_stateHandlerB05(int* obj, GroundBaddieState* state);
int iceBaddie_stateHandlerB06(int obj, int state);
int iceBaddie_stateHandlerB07(int obj, int state);

#endif /* MAIN_DLL_ICEBADDIE_H_ */
