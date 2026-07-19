#ifndef MAIN_DLL_TRICKY_SUBSTATES_H_
#define MAIN_DLL_TRICKY_SUBSTATES_H_

#include "main/game_object.h"
#include "ghidra_import.h"

void trickyDigTunnel(u8* obj, u8* state);
void tricky_stateFindSecretDig(u8* obj, u8* state);
void tricky_stateFollowPlayer(u8* obj, u8* state);
int tricky_substateApproachThorntail(int obj, int state);
int tricky_substateFlameBreath(u8* obj, u8* state);
int tricky_substateBegForFood(GameObject* obj, int state);
int tricky_substateDigForFood(GameObject* obj, int state);
int tricky_substateIdlePick(u8* obj, u8* state);
u32 tricky_substateFidgetA(GameObject* param_1, int* param_2);
u32 tricky_substateFidgetB(GameObject* param_1, int* param_2);
u32 tricky_substateWaitMoveEnd(GameObject* param_1, int* param_2);
int tricky_substateHowlCall(GameObject* param_1, int* param_2);
int tricky_substateSleep(GameObject* obj, int* state);
u32 tricky_substateWaitQueuedMove(GameObject* param_1, int* param_2);
u32 tricky_substateReturnToHeel(GameObject* param_1, int* param_2);
int tricky_substateFollowIdle(GameObject* obj, int state);
u32 tricky_updateIdleBehavior(int param_1, int* param_2);
void tricky_pickAmbientActivity(u8* obj, u8* state);
void tricky_startRandomIdleMove(GameObject* param_1, int param_2);
int tricky_handleFeedOrTalk(GameObject* param_1, int* param_2);

#endif /* MAIN_DLL_TRICKY_SUBSTATES_H_ */
