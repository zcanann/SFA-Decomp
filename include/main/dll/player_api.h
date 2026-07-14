#ifndef MAIN_DLL_PLAYER_API_H_
#define MAIN_DLL_PLAYER_API_H_

#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/dll/player_staff_api.h"

int objFn_802962b4(GameObject* obj);
int fn_80295A04(GameObject* obj, int selector);
int fn_80295C0C(GameObject* obj);
int fn_80295C88(GameObject* player);
int playerIsPathFollowing(GameObject* player);
void fn_802960E8(GameObject* player, s16 effectId);
f32 fn_8029610C(GameObject* obj);
void fn_802961A4(GameObject* obj, int* outMove, f32* outChargeLevel);
int objGetAnimState80A(GameObject* obj);
int objGetAnimStateFlags(GameObject* obj, int flag);
int objIsCurModelNotZero(void* obj);
int Obj_IsParentSlackClear(GameObject* obj);
int EmissionController_IsLingering(GameObject* obj);
int playerGetFlags3F0Bit5(GameObject* obj);
u32 playerGetStateFlag310(GameObject* obj);
u8 fn_80296414(GameObject* player, GameObject* otherObj, u8* outDirection);
int fn_80296464(GameObject* player);
int fn_802969F0(GameObject* player);
void fn_80296A9C(GameObject* player, int delta);
GameObject* playerGetFocusObject(GameObject* player);
int playerGetMoney(GameObject* player);
int playerHasSpell(GameObject* obj, int spell);
int playerIsDisguised(GameObject* obj);
void playerSetDisguised(GameObject* obj, int mode);
void playerAddMoney(GameObject* obj, int amount);
void playerAddHealth(GameObject* obj, int amount);
void playerAddRemoveMagic(GameObject* obj, int amount);
void playerCancelSpell(GameObject* obj, int spell);
void playerHeal(GameObject* obj);
int playerGetTimeScale(GameObject* obj, f32* out);
int isTrickyNear(GameObject* obj);
int fn_8029669C(GameObject* obj);
int fn_802966B4(GameObject* obj);
int objFn_80296700(GameObject* obj);
int fn_80296C4C(GameObject* obj);
void fn_80296D20(GameObject* player, GameObject* parentObj);
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
