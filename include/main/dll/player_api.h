#ifndef MAIN_DLL_PLAYER_API_H_
#define MAIN_DLL_PLAYER_API_H_

#include "game/objects/object.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"
#include "main/dll/player_staff_api.h"

#define PLAYER_STATE_FLAG_CAN_PLACE_CARRYABLE 0x4000

int playerIsInNormalControlUndisguisedOnLand(GameObject* player);
int playerIsInNormalControl(GameObject* obj);
void playerSetStateValue(GameObject* player, int selector, f32 value);
int playerGetStateValue(GameObject* obj, int selector);
int playerCanEnterStaffCombatCamera(GameObject* player);
int playerIsTargetSuppressed(GameObject* player);
int playerIsInWater(GameObject* player);
int playerIsQuakeShockwaveActive(GameObject* player);
int playerFindNearestFirefly(GameObject* player);
int playerIsClimbingWall(GameObject* player);
int playerIsPathFollowing(GameObject* player);
void playerRender(int obj, int a, int b, int c, int d, int flag);
void playerLock(GameObject* player, int lock);
int playerGetAimScreenPos(GameObject* player, f32* outX, f32* outY);
void playerSetPendingBoneEffect(GameObject* player, s16 effectId);
void playerApplyHorizontalVelocity_nop(int obj, f32 xVelocity, f32 zVelocity);
void playerGetFxOffsets(GameObject* player, f32** outFxOffsets);
void objSetPos(GameObject* player, f32 x, f32 y, f32 z);
f32 playerGetAnimSpeed(GameObject* obj);
void playerTeleport(GameObject* player, const Vec3f* position, const Vec3s* rotation, int unused);
void playerGetMoveAndChargeLevel(GameObject* obj, int* outMove, f32* outChargeLevel);
int objGetAnimState80A(GameObject* obj);
int objGetAnimStateFlags(GameObject* obj, int flag);
int objIsCurModelNotZero(void* obj);
int Obj_IsParentSlackClear(GameObject* obj);
int EmissionController_IsLingering(GameObject* obj);
int playerGetFlags3F0Bit5(GameObject* obj);
u32 playerGetStateFlag310(GameObject* obj);
u8 playerIsPushingObject(GameObject* player, GameObject* otherObj, u8* outDirection);
int playerIsSequenceRenderSuppressed(GameObject* player);
int playerGetSurfaceType(GameObject* player);
void playerAddMaxMagic(GameObject* player, int delta);
void playerDisableHitDetect(GameObject* player);
void playerGetAttackHitProperties(GameObject* player, u32* outEffects, f32* outReaction, f32* outKnockbackSpeed,
                                  f32* outDrag, u16* outHitStunFrames);
GameObject* playerGetFocusObject(GameObject* player);
int playerGetMoney(GameObject* player);
int playerHasSpell(GameObject* obj, int spell);
void playerSetHaveSpell(GameObject* obj, int spell, int set);
int playerIsDisguised(GameObject* obj);
void playerSetDisguised(GameObject* obj, int mode);
void playerAddMoney(GameObject* obj, int amount);
void playerAddHealth(GameObject* obj, int amount);
void playerAddRemoveMagic(GameObject* obj, int amount);
void playerCancelSpell(GameObject* obj, int spell);
void playerHeal(GameObject* obj);
int playerGetTimeScale(GameObject* obj, f32* out);
int isTrickyNear(GameObject* obj);
int playerIsThrowing(GameObject* obj);
int playerIsPuttingDown(GameObject* obj);
int playerIsStaffActionPending(GameObject* obj);
int playerIsNotAttacking(GameObject* player);
int playerCanUseCombatTargeting(GameObject* player);
f32 playerGetProbeHitDist(GameObject* player);
int playerIsDead(GameObject* obj);
void playerReleaseLedgeGrabOn(GameObject* player, GameObject* parentObj);
void playerSetInCutscene(GameObject* player);
void playerSetCutsceneCameraFlag(GameObject* player);
void playerSetOverrideParentSlack(GameObject* player);
void cameraGetPrevPos2(GameObject* player, f32* outX, f32* outY, f32* outZ);
void objSetAnimStateFlags(GameObject* obj, int flag, int set);
void playerInitFuncPtrsEntry(void);
void playerRenderFuzz(GameObject* obj, int p2, int fuzzPass);
void playerFree(GameObject* obj, int flag);
void playerUpdateWhileTimeStopped(GameObject* obj);
void objLoadPlayerFromSave(GameObject* obj);
void playerReparentPreservingWorldTransform(GameObject* obj, GameObject* newParent);

int Lightfoot_UpdateProximityInteractionState(GameObject* obj, BaddieState* state);
int Lightfoot_UpdateCompletionInteraction(GameObject* obj, BaddieState* state);
int Lightfoot_UpdateChallengeGateInteraction(GameObject* obj, BaddieState* state);
int Lightfoot_UpdateWanderSteering(GameObject* obj, BaddieState* state, f32 fv);
int Lightfoot_UpdateRandomTurn(GameObject* obj, BaddieState* state, f32 fv);
int Lightfoot_UpdateTargetAnimationCycle(GameObject* obj, BaddieState* state, f32 fv);
int Lightfoot_UpdateButtonTimingChallenge(GameObject* obj, BaddieState* state, f32 fv);
int Lightfoot_UpdateAnimationCycle(GameObject* obj, BaddieState* state, f32 fv);
void Lightfoot_RecordCompletedChallengeTargetHit(GameObject* obj, GroundBaddieState* inner,
                                                 struct LightfootControlState* animState);
void Lightfoot_ProcessHitResponseFlags(GameObject* obj, BaddieState* inner);
void Lightfoot_ResetScriptedPosition(GameObject* obj);
void Lightfoot_UpdateAttachedChild(GameObject* obj, GroundBaddieState* inner);
void Lightfoot_UpdatePlayerInteraction(GameObject* obj, GroundBaddieState* inner, BaddieState* state);
int Lightfoot_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);

#endif /* MAIN_DLL_PLAYER_API_H_ */
