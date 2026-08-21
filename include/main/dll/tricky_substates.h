#ifndef MAIN_DLL_TRICKY_SUBSTATES_H_
#define MAIN_DLL_TRICKY_SUBSTATES_H_

#include "game/objects/object.h"
#include "types.h"
#include "main/dll/tricky_state.h"

void trickyDigTunnel(GameObject* obj, TrickyState* state);
void tricky_stateFindSecretDig(GameObject* obj, TrickyState* state);
void tricky_stateFollowPlayer(GameObject* obj, TrickyState* state);
int tricky_substateApproachThorntail(GameObject* obj, TrickyState* state);
int tricky_substateFlameBreath(GameObject* obj, TrickyState* state);
int tricky_substateBegForFood(GameObject* obj, TrickyState* state);
int tricky_substateDigForFood(GameObject* obj, TrickyState* state);
int tricky_substateIdlePick(GameObject* obj, TrickyState* state);
u32 tricky_substateFidgetA(GameObject* obj, TrickyState* trickyState);
u32 tricky_substateFidgetB(GameObject* obj, TrickyState* trickyState);
u32 tricky_substateWaitMoveEnd(GameObject* obj, TrickyState* trickyState);
int tricky_substateHowlCall(GameObject* obj, TrickyState* trickyState);
int tricky_substateSleep(GameObject* obj, TrickyState* state);
u32 tricky_substateWaitQueuedMove(GameObject* obj, TrickyState* trickyState);
u32 tricky_substateReturnToHeel(GameObject* obj, TrickyState* trickyState);
int tricky_substateFollowIdle(GameObject* obj, TrickyState* state);
u32 tricky_updateIdleBehavior(GameObject* obj, TrickyState* trickyState);
void tricky_pickAmbientActivity(GameObject* obj, TrickyState* state);
void tricky_startRandomIdleMove(GameObject* obj, TrickyState* trickyState);
int tricky_handleFeedOrTalk(GameObject* obj, TrickyState* state);

#endif /* MAIN_DLL_TRICKY_SUBSTATES_H_ */
