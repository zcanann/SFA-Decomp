#ifndef MAIN_DLL_PLAYER_API_H_
#define MAIN_DLL_PLAYER_API_H_

#include "main/game_object.h"
#include "main/objanim_update.h"

int objFn_802962b4(GameObject* obj);
int objGetAnimState80A(GameObject* obj);
u8 fn_80296414(GameObject* player, GameObject* otherObj, u8* outDirection);
int fn_802969F0(GameObject* player);
void fn_80296A9C(GameObject* player, int delta);
GameObject* playerGetFocusObject(GameObject* player);
int playerGetMoney(void* player);
void playerAddMoney(GameObject* obj, int amount);
void playerAddHealth(GameObject* obj, int amount);
void objSetAnimStateFlags(GameObject* obj, int flag, int set);
/* The raw integer parent preserves the matched player implementation's signed comparisons. */
void fn_80296EB4(GameObject* obj, int newParent);

int Lightfoot_UpdateProximityInteractionState(int obj, int state);
int Lightfoot_UpdateCompletionInteraction(int obj, int state);
int Lightfoot_UpdateChallengeGateInteraction(int obj, int state);
int Lightfoot_UpdateWanderSteering(GameObject* obj, int state, f32 fv);
int Lightfoot_UpdateRandomTurn(int obj, int state, f32 fv);
int Lightfoot_UpdateTargetAnimationCycle(GameObject* obj, int state, f32 fv);
int Lightfoot_UpdateButtonTimingChallenge(GameObject* obj, int state, f32 fv);
int Lightfoot_UpdateAnimationCycle(GameObject* obj, int state, f32 fv);
void Lightfoot_RecordCompletedChallengeTargetHit(GameObject* obj, int inner, int animState);
void Lightfoot_ProcessHitResponseFlags(int obj, int inner);
void Lightfoot_ResetScriptedPosition(GameObject* obj);
void Lightfoot_UpdateAttachedChild(GameObject* obj, int inner);
void Lightfoot_UpdatePlayerInteraction(int obj, int inner, int state);
int Lightfoot_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_PLAYER_API_H_ */
