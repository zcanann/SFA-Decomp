/*
 * CClightfoot (DLL 0x188) - Lightfoot combatant from the CloudRunner
 * encounter. Each instance selects between the player and two encounter
 * actors, attaches a Lightfoot weapon, and runs a reaction-oriented combat
 * state machine.
 */
#include "dlls/objects/392_CClightfoot.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dlls/objects/201_Baddie.h"
#include "main/dll/player_api.h"
#include "main/dll/player_target.h"
#include "main/dll/waterfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/obj_link.h"
#include "main/obj_trigger.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define CC_LIGHTFOOT_ENCOUNTER_TRIGGERED_GAMEBIT 9
#define CC_LIGHTFOOT_ENCOUNTER_DESPAWN_GAMEBIT   0x24

#define CC_LIGHTFOOT_TARGET_ACTOR_A_ID 0x45D7D
#define CC_LIGHTFOOT_TARGET_ACTOR_B_ID 0x45D7F

#define CC_LIGHTFOOT_WEAPON_OBJECT_DEF 0x6F1
#define CC_LIGHTFOOT_WEAPON_SETUP_SIZE 0x20

#define CC_LIGHTFOOT_PHASE_INIT         0
#define CC_LIGHTFOOT_PHASE_INTRO        1
#define CC_LIGHTFOOT_PHASE_APPROACH     2
#define CC_LIGHTFOOT_PHASE_CLOSE        3
#define CC_LIGHTFOOT_PHASE_ENGAGE       4
#define CC_LIGHTFOOT_PHASE_GUARD        5
#define CC_LIGHTFOOT_PHASE_GUARD_HELD   6
#define CC_LIGHTFOOT_PHASE_STRIKE_WATCH 7
#define CC_LIGHTFOOT_PHASE_PARRY        8
#define CC_LIGHTFOOT_PHASE_PARRY_HELD   9
#define CC_LIGHTFOOT_PHASE_RECOVER      0xA
#define CC_LIGHTFOOT_PHASE_REACT        0xB
#define CC_LIGHTFOOT_PHASE_DORMANT      0xC
#define CC_LIGHTFOOT_PHASE_DORMANT_TURN 0xD
#define CC_LIGHTFOOT_PHASE_DESPAWN      0xE

#define CC_LIGHTFOOT_FLAG_MOVE_COMPLETE 0x01
#define CC_LIGHTFOOT_FLAG_TURN_REQUIRED 0x02

#define CC_LIGHTFOOT_ANIM_FLAG_INTERACTION_DISABLED 0x01
#define CC_LIGHTFOOT_ANIM_FLAG_START_AT_END         0x02

#define CC_LIGHTFOOT_DISTANCE_SENTINEL           3.40282347e+38f
#define CC_LIGHTFOOT_COMBAT_DISTANCE_SQUARED     3025.0f
#define CC_LIGHTFOOT_ALERT_DISTANCE_SQUARED      32400.0f
#define CC_LIGHTFOOT_HIT_EFFECT_DISTANCE_SQUARED 20000.0f
#define CC_LIGHTFOOT_STRIKE_PROGRESS_THRESHOLD   0.2f
#define CC_LIGHTFOOT_TURN_PROGRESS_START         0.2f
#define CC_LIGHTFOOT_TURN_PROGRESS_END           0.8f
#define CC_LIGHTFOOT_TURN_RATE                   1024.0f
#define CC_LIGHTFOOT_TURN_REQUIRED_ANGLE         0x1000
#define CC_LIGHTFOOT_TURN_SNAP_ANGLE             0x400
#define CC_LIGHTFOOT_HALF_TURN                   0x8000
#define CC_LIGHTFOOT_ANGLE_WRAP                  0xFFFF
#define CC_LIGHTFOOT_IDLE_SFX_DELAY_MIN          0xB4
#define CC_LIGHTFOOT_IDLE_SFX_DELAY_MAX          0x12C
#define CC_LIGHTFOOT_HIT_LIGHT_SCALE             0.014f
#define CC_LIGHTFOOT_ANIMATION_PROGRESS_START    0.0f
#define CC_LIGHTFOOT_ANIMATION_PROGRESS_END      1.0f
#define CC_LIGHTFOOT_WATER_SPLASH_SCALE          15.0f
#define CC_LIGHTFOOT_ROT_X_SHIFT                 8

#define CC_LIGHTFOOT_TARGET_GUARD_MOVE  0x19
#define CC_LIGHTFOOT_TARGET_STRIKE_MOVE 0x18

#define CC_LIGHTFOOT_ANIM_EVENT_DETACH_WEAPON 1
#define CC_LIGHTFOOT_ANIM_EVENT_WATER_SPLASH  2

#define CC_LIGHTFOOT_HIT_SEQ_COLOR_FADE_A 0x11
#define CC_LIGHTFOOT_HIT_SEQ_COLOR_FADE_B 0x33

typedef struct CCLightfootHitCooldown {
    f32 cooldown;
    u8 unknown04[4];
} CCLightfootHitCooldown;

STATIC_ASSERT(sizeof(CCLightfootHitCooldown) == 0x08);
STATIC_ASSERT(offsetof(CCLightfootHitCooldown, cooldown) == 0x00);
STATIC_ASSERT(offsetof(CCLightfootHitCooldown, unknown04) == 0x04);

typedef struct CCLightfootAnimTable {
    u8 phaseFlags[0x10];
    u8 moveIds[0x10];
    f32 moveSpeeds[15];
} CCLightfootAnimTable;

STATIC_ASSERT(sizeof(CCLightfootAnimTable) == 0x5C);
STATIC_ASSERT(offsetof(CCLightfootAnimTable, phaseFlags) == 0x00);
STATIC_ASSERT(offsetof(CCLightfootAnimTable, moveIds) == 0x10);
STATIC_ASSERT(offsetof(CCLightfootAnimTable, moveSpeeds) == 0x20);

int ccLightfoot_animationEventCallback(GameObject* obj, int unusedArg, ObjSeqState* animUpdate) {
    CCLightfootState* state = obj->extra;

    if (animUpdate->eventCount != 0) {
        int eventIndex;

        for (eventIndex = 0; (u8)eventIndex < animUpdate->eventCount; eventIndex++) {
            int eventId = animUpdate->eventIds[(u8)eventIndex];

            switch (eventId) {
            case CC_LIGHTFOOT_ANIM_EVENT_DETACH_WEAPON:
                if (obj->childObjs[0] != NULL) {
                    ObjLink_DetachChild(obj, state->attachedWeapon);
                }
                break;
            case CC_LIGHTFOOT_ANIM_EVENT_WATER_SPLASH:
                (*gWaterfxInterface)
                    ->spawnSplashBurst((void*)obj, obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ,
                                       CC_LIGHTFOOT_WATER_SPLASH_SCALE);
                break;
            }
        }
    }
    return 0;
}

int ccLightfoot_getExtraSize(void) {
    return sizeof(CCLightfootState);
}

void ccLightfoot_free(GameObject* obj, int keepWeapon) {
    CCLightfootState* state = obj->extra;
    GameObject* weapon = state->attachedWeapon;

    if (weapon != NULL) {
        if (obj->childObjs[0] != NULL) {
            ObjLink_DetachChild(obj, weapon);
        }
        if (keepWeapon == 0) {
            Obj_FreeObject(state->attachedWeapon);
        }
    }
}

CCLightfootHitCooldown gCCLightfootHitCooldown;

CCLightfootAnimTable gCCLightfootAnimTable = {
    {1, 1, 1, 1, 1, 1, 1, 3, 1, 1, 3, 1, 0, 1, 1, 0},
    {0, 3, 1, 5, 4, 6, 8, 6, 7, 9, 7, 2, 0, 3, 0, 0},
    {0.01f, 0.015f, 0.02f, 0.02f, 0.02f, 0.02f, 0.01f, -0.02f, 0.05f, 0.01f, -0.02f, 0.01f, 0.01f, 0.015f, 0.02f},
};

ObjectDescriptor gCCLightfootObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)ccLightfoot_init,
    (ObjectDescriptorCallback)ccLightfoot_update,
    0,
    0,
    (ObjectDescriptorCallback)ccLightfoot_free,
    0,
    ccLightfoot_getExtraSize,
};

void ccLightfoot_selectCombatPhase(CCLightfootState* state, GameObject* targetObject, f32 distanceSquared) {
    s16 move;

    if (CC_LIGHTFOOT_DISTANCE_SENTINEL == distanceSquared) {
        state->phase = CC_LIGHTFOOT_PHASE_DORMANT;
        return;
    }
    if ((state->flags & CC_LIGHTFOOT_FLAG_TURN_REQUIRED) != 0) {
        state->phase = CC_LIGHTFOOT_PHASE_INTRO;
        return;
    }
    if (distanceSquared < CC_LIGHTFOOT_COMBAT_DISTANCE_SQUARED) {
        move = targetObject->anim.currentMove;
        if (move == CC_LIGHTFOOT_TARGET_STRIKE_MOVE &&
            targetObject->anim.currentMoveProgress > CC_LIGHTFOOT_STRIKE_PROGRESS_THRESHOLD) {
            state->phase = CC_LIGHTFOOT_PHASE_PARRY;
            return;
        }
        if (move == CC_LIGHTFOOT_TARGET_GUARD_MOVE) {
            state->phase = CC_LIGHTFOOT_PHASE_GUARD;
            return;
        }
        state->phase = CC_LIGHTFOOT_PHASE_REACT;
        return;
    }
    state->phase = CC_LIGHTFOOT_PHASE_APPROACH;
}

void ccLightfoot_update(GameObject* obj) {
    CCLightfootAnimTable* animTable = &gCCLightfootAnimTable;
    u32 singleTarget;
    CCLightfootState* state = obj->extra;
    GameObject* targetObject;
    s16 targetAngle;
    GameObject* candidateTarget;
    GameObject* targetActorAHandle;
    u32 farTarget;
    u32 nearTarget;
    s16 angleDifference;
    int targetValid;
    u32 targetByteOffset;
    u8 targetIndex;
    f32 distanceSquared;
    GameObject* hitObjectHandle;
    f32 targetDistanceSquares[2];
    f32 hitPos[3];
    int moveId;
    s16 move;
    u8 phase;

    singleTarget = 0;
    if ((animTable->phaseFlags[state->phase] & CC_LIGHTFOOT_ANIM_FLAG_INTERACTION_DISABLED) != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    } else {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    }
    targetActorAHandle = state->targetActorA;
    if (targetActorAHandle != 0) {
        do {
            if (!(enemy_getHealthFraction((GameObject*)targetActorAHandle) > 0.0f)) {
                targetValid = 0;
            } else {
                targetValid = mainGetBit(targetActorAHandle->anim.placementData[0xC]) != 0 ? 0 : 1;
            }
            if (targetValid != 0) {
                candidateTarget = state->targetActorB;
                if (!(enemy_getHealthFraction((GameObject*)candidateTarget) > 0.0f)) {
                    targetValid = 0;
                } else {
                    targetValid = mainGetBit(candidateTarget->anim.placementData[0xC]) != 0 ? 0 : 1;
                }
                if (targetValid != 0) {
                    distanceSquared =
                        getXZDistanceSquared(&state->playerObject->anim.worldPosX,
                                      &state->targetActorB->anim.worldPosX);
                    if (getXZDistanceSquared(&state->playerObject->anim.worldPosX,
                                      &state->targetActorA->anim.worldPosX) <
                        distanceSquared) {
                        nearTarget = (u32)state->targetActorA;
                        farTarget = (u32)state->targetActorB;
                    } else {
                        nearTarget = (u32)state->targetActorB;
                        farTarget = (u32)state->targetActorA;
                    }
                    if ((getXZDistanceSquared(&obj->anim.worldPosX,
                                       &state->playerObject->anim.worldPosX) <
                             CC_LIGHTFOOT_ALERT_DISTANCE_SQUARED ||
                         (void*)playerGetTargetObject((GameObject*)state->playerObject) == (void*)state->targetActorA ||
                         (void*)playerGetTargetObject((GameObject*)state->playerObject) == (void*)state->targetActorB) &&
                        playerIsDisguised((GameObject*)state->playerObject) == 0) {
                        if ((void*)playerGetTargetObject((GameObject*)state->playerObject) == (void*)farTarget) {
                            u32 tmp = farTarget ^ nearTarget;
                            nearTarget ^= tmp;
                            farTarget = tmp ^ nearTarget;
                        }
                        enemy_setTrackedObj((GameObject*)nearTarget, (GameObject*)state->playerObject);
                        enemy_setTrackedObj((GameObject*)farTarget, obj);
                        targetObject = (GameObject*)farTarget;
                        distanceSquared = getXZDistanceSquared(&obj->anim.worldPosX,
                                                        (f32*)(farTarget + offsetof(GameObject, anim.worldPosX)));
                    } else {
                        for (targetIndex = 0; targetIndex < 2; targetIndex++) {
                            targetByteOffset = targetIndex * 4;
                            *(f32*)((u8*)targetDistanceSquares + targetByteOffset) = getXZDistanceSquared(
                                &obj->anim.worldPosX, (f32*)(*(int*)((u8*)state + targetByteOffset +
                                                                     offsetof(CCLightfootState, targetActors)) +
                                                             offsetof(GameObject, anim.worldPosX)));
                            enemy_setTrackedObj((GameObject*)*(int*)((u8*)state + targetByteOffset +
                                                                     offsetof(CCLightfootState, targetActors)),
                                                obj);
                        }
                        if (targetDistanceSquares[0] < targetDistanceSquares[1]) {
                            targetObject = state->targetActorA;
                            distanceSquared = targetDistanceSquares[0];
                        } else {
                            targetObject = state->targetActorB;
                            distanceSquared = targetDistanceSquares[1];
                        }
                    }
                    break;
                }
            }
            candidateTarget = state->targetActorA;
            if (!(enemy_getHealthFraction((GameObject*)candidateTarget) > 0.0f)) {
                targetValid = 0;
            } else {
                targetValid = mainGetBit(candidateTarget->anim.placementData[0xC]) != 0 ? 0 : 1;
            }
            if (targetValid != 0) {
                singleTarget = (u32)state->targetActorA;
            }
            candidateTarget = state->targetActorB;
            if (!(enemy_getHealthFraction((GameObject*)candidateTarget) > 0.0f)) {
                targetValid = 0;
            } else {
                targetValid = mainGetBit(candidateTarget->anim.placementData[0xC]) != 0 ? 0 : 1;
            }
            if (targetValid != 0) {
                singleTarget = (u32)state->targetActorB;
            }
            if (singleTarget != 0) {
                distanceSquared = getXZDistanceSquared(&state->playerObject->anim.worldPosX,
                                                (f32*)(singleTarget + offsetof(GameObject, anim.worldPosX)));
                if ((getXZDistanceSquared(&obj->anim.worldPosX, (f32*)(singleTarget + offsetof(GameObject, anim.worldPosX))) <
                         distanceSquared &&
                     (void*)playerGetTargetObject((GameObject*)state->playerObject) != (void*)singleTarget) ||
                    playerIsDisguised((GameObject*)state->playerObject) != 0) {
                    enemy_setTrackedObj((GameObject*)singleTarget, obj);
                } else {
                    enemy_setTrackedObj((GameObject*)singleTarget, (GameObject*)state->playerObject);
                }
                targetObject = (GameObject*)singleTarget;
                distanceSquared =
                    getXZDistanceSquared(&obj->anim.worldPosX, (f32*)(singleTarget + offsetof(GameObject, anim.worldPosX)));
            } else {
                targetObject = state->playerObject;
                distanceSquared = CC_LIGHTFOOT_DISTANCE_SENTINEL;
            }
        } while (0);
        targetAngle = getAngle(-(targetObject->anim.localPosX - obj->anim.localPosX),
                               -(targetObject->anim.localPosZ - obj->anim.localPosZ));
        angleDifference = (s16)(obj->anim.rotX - (u16)targetAngle);
        if (angleDifference > CC_LIGHTFOOT_HALF_TURN) {
            angleDifference = (s16)(angleDifference - CC_LIGHTFOOT_ANGLE_WRAP);
        }
        if (angleDifference < -CC_LIGHTFOOT_HALF_TURN) {
            angleDifference = (s16)(angleDifference + CC_LIGHTFOOT_ANGLE_WRAP);
        }
        if (angleDifference > CC_LIGHTFOOT_TURN_REQUIRED_ANGLE) {
            state->flags |= CC_LIGHTFOOT_FLAG_TURN_REQUIRED;
        } else if (angleDifference < -CC_LIGHTFOOT_TURN_REQUIRED_ANGLE) {
            state->flags |= CC_LIGHTFOOT_FLAG_TURN_REQUIRED;
        } else {
            state->flags &= ~CC_LIGHTFOOT_FLAG_TURN_REQUIRED;
        }
    }
    if (state->phase <= CC_LIGHTFOOT_PHASE_REACT) {
        state->idleSfxTimer -= timeDelta;
        if (state->idleSfxTimer < 0.0f) {
            state->idleSfxTimer =
                randomGetRange(CC_LIGHTFOOT_IDLE_SFX_DELAY_MIN, CC_LIGHTFOOT_IDLE_SFX_DELAY_MAX);
            Sfx_PlayFromObject(obj, SFXTRIG_trwhin4);
        }
    }
    switch (state->phase) {
    case CC_LIGHTFOOT_PHASE_INIT:
        if (mainGetBit(CC_LIGHTFOOT_ENCOUNTER_TRIGGERED_GAMEBIT) != 0) {
            state->phase = CC_LIGHTFOOT_PHASE_DESPAWN;
        } else {
            if ((u8)Obj_CanSetupObject() != 0) {
                state->attachedWeapon = objSetupObject(
                    Obj_AllocObjectSetup(CC_LIGHTFOOT_WEAPON_SETUP_SIZE, CC_LIGHTFOOT_WEAPON_OBJECT_DEF), 5, -1, -1,
                    obj->anim.parent);
                ObjLink_AttachChild(obj, state->attachedWeapon, 0);
            }
            state->playerObject = Obj_GetPlayerObject();
            state->targetActorA = ObjList_FindObjectById(CC_LIGHTFOOT_TARGET_ACTOR_A_ID);
            state->targetActorB = ObjList_FindObjectById(CC_LIGHTFOOT_TARGET_ACTOR_B_ID);
            state->phase = CC_LIGHTFOOT_PHASE_INTRO;
            state->idleSfxTimer =
                randomGetRange(CC_LIGHTFOOT_IDLE_SFX_DELAY_MIN, CC_LIGHTFOOT_IDLE_SFX_DELAY_MAX);
        }
        break;
    case CC_LIGHTFOOT_PHASE_INTRO:
        if (obj->anim.currentMoveProgress > CC_LIGHTFOOT_TURN_PROGRESS_START &&
            obj->anim.currentMoveProgress < CC_LIGHTFOOT_TURN_PROGRESS_END) {
            if (angleDifference > CC_LIGHTFOOT_TURN_SNAP_ANGLE) {
                obj->anim.rotX = (s16)(obj->anim.rotX - (int)(CC_LIGHTFOOT_TURN_RATE * timeDelta));
            } else if (angleDifference < -CC_LIGHTFOOT_TURN_SNAP_ANGLE) {
                obj->anim.rotX = (s16)(obj->anim.rotX + (int)(CC_LIGHTFOOT_TURN_RATE * timeDelta));
            } else {
                obj->anim.rotX = targetAngle;
            }
        }
        if ((state->flags & CC_LIGHTFOOT_FLAG_MOVE_COMPLETE) != 0) {
            ccLightfoot_selectCombatPhase(state, targetObject, distanceSquared);
        }
        break;
    case CC_LIGHTFOOT_PHASE_APPROACH:
        if ((state->flags & CC_LIGHTFOOT_FLAG_MOVE_COMPLETE) != 0) {
            if (distanceSquared < CC_LIGHTFOOT_COMBAT_DISTANCE_SQUARED) {
                state->phase = CC_LIGHTFOOT_PHASE_ENGAGE;
            } else {
                state->phase = CC_LIGHTFOOT_PHASE_CLOSE;
            }
        }
        break;
    case CC_LIGHTFOOT_PHASE_CLOSE:
        if ((state->flags & CC_LIGHTFOOT_FLAG_MOVE_COMPLETE) != 0) {
            state->phase = CC_LIGHTFOOT_PHASE_ENGAGE;
        }
        break;
    case CC_LIGHTFOOT_PHASE_ENGAGE:
        if ((state->flags & CC_LIGHTFOOT_FLAG_MOVE_COMPLETE) != 0) {
            ccLightfoot_selectCombatPhase(state, targetObject, distanceSquared);
        }
        break;
    case CC_LIGHTFOOT_PHASE_GUARD:
        if (targetObject->anim.currentMove != CC_LIGHTFOOT_TARGET_GUARD_MOVE) {
            state->phase = CC_LIGHTFOOT_PHASE_STRIKE_WATCH;
        }
        if ((state->flags & CC_LIGHTFOOT_FLAG_MOVE_COMPLETE) != 0) {
            state->phase = CC_LIGHTFOOT_PHASE_GUARD_HELD;
        }
        break;
    case CC_LIGHTFOOT_PHASE_GUARD_HELD:
        if (targetObject->anim.currentMove != CC_LIGHTFOOT_TARGET_GUARD_MOVE) {
            state->phase = CC_LIGHTFOOT_PHASE_STRIKE_WATCH;
        }
        break;
    case CC_LIGHTFOOT_PHASE_STRIKE_WATCH:
        move = targetObject->anim.currentMove;
        if (move == CC_LIGHTFOOT_TARGET_STRIKE_MOVE &&
            targetObject->anim.currentMoveProgress > CC_LIGHTFOOT_STRIKE_PROGRESS_THRESHOLD) {
            state->phase = CC_LIGHTFOOT_PHASE_PARRY;
        } else if (move == CC_LIGHTFOOT_TARGET_GUARD_MOVE) {
            state->phase = CC_LIGHTFOOT_PHASE_GUARD;
        } else if ((state->flags & CC_LIGHTFOOT_FLAG_MOVE_COMPLETE) != 0) {
            ccLightfoot_selectCombatPhase(state, targetObject, distanceSquared);
        }
        break;
    case CC_LIGHTFOOT_PHASE_PARRY:
        move = targetObject->anim.currentMove;
        if (move != CC_LIGHTFOOT_TARGET_STRIKE_MOVE ||
            (move == CC_LIGHTFOOT_TARGET_STRIKE_MOVE &&
             targetObject->anim.currentMoveProgress < CC_LIGHTFOOT_STRIKE_PROGRESS_THRESHOLD)) {
            state->phase = CC_LIGHTFOOT_PHASE_RECOVER;
        }
        if ((state->flags & CC_LIGHTFOOT_FLAG_MOVE_COMPLETE) != 0) {
            state->phase = CC_LIGHTFOOT_PHASE_PARRY_HELD;
        }
        break;
    case CC_LIGHTFOOT_PHASE_PARRY_HELD:
        move = targetObject->anim.currentMove;
        if (move != CC_LIGHTFOOT_TARGET_STRIKE_MOVE ||
            (move == CC_LIGHTFOOT_TARGET_STRIKE_MOVE &&
             targetObject->anim.currentMoveProgress < CC_LIGHTFOOT_STRIKE_PROGRESS_THRESHOLD)) {
            state->phase = CC_LIGHTFOOT_PHASE_RECOVER;
        }
        break;
    case CC_LIGHTFOOT_PHASE_RECOVER:
        move = targetObject->anim.currentMove;
        if (move == CC_LIGHTFOOT_TARGET_STRIKE_MOVE &&
            targetObject->anim.currentMoveProgress > CC_LIGHTFOOT_STRIKE_PROGRESS_THRESHOLD) {
            state->phase = CC_LIGHTFOOT_PHASE_PARRY;
        } else if (move == CC_LIGHTFOOT_TARGET_GUARD_MOVE) {
            state->phase = CC_LIGHTFOOT_PHASE_GUARD;
        } else if ((state->flags & CC_LIGHTFOOT_FLAG_MOVE_COMPLETE) != 0) {
            ccLightfoot_selectCombatPhase(state, targetObject, distanceSquared);
        }
        break;
    case CC_LIGHTFOOT_PHASE_REACT:
        ccLightfoot_selectCombatPhase(state, targetObject, distanceSquared);
        break;
    case CC_LIGHTFOOT_PHASE_DORMANT:
        if (mainGetBit(CC_LIGHTFOOT_ENCOUNTER_TRIGGERED_GAMEBIT) != 0) {
            if (mainGetBit(CC_LIGHTFOOT_ENCOUNTER_DESPAWN_GAMEBIT) != 0) {
                state->phase = CC_LIGHTFOOT_PHASE_DESPAWN;
            }
        } else if (ObjTrigger_IsSet(obj) != 0) {
            mainSetBits(CC_LIGHTFOOT_ENCOUNTER_TRIGGERED_GAMEBIT, 1);
        } else if ((state->flags & CC_LIGHTFOOT_FLAG_TURN_REQUIRED) != 0) {
            state->phase = CC_LIGHTFOOT_PHASE_DORMANT_TURN;
        }
        break;
    case CC_LIGHTFOOT_PHASE_DORMANT_TURN:
        if (obj->anim.currentMoveProgress > CC_LIGHTFOOT_TURN_PROGRESS_START &&
            obj->anim.currentMoveProgress < CC_LIGHTFOOT_TURN_PROGRESS_END) {
            if (angleDifference > CC_LIGHTFOOT_TURN_SNAP_ANGLE) {
                obj->anim.rotX = (s16)(obj->anim.rotX - (int)(CC_LIGHTFOOT_TURN_RATE * timeDelta));
            } else if (angleDifference < -CC_LIGHTFOOT_TURN_SNAP_ANGLE) {
                obj->anim.rotX = (s16)(obj->anim.rotX + (int)(CC_LIGHTFOOT_TURN_RATE * timeDelta));
            } else {
                obj->anim.rotX = targetAngle;
            }
        }
        if ((state->flags & CC_LIGHTFOOT_FLAG_MOVE_COMPLETE) != 0) {
            state->phase = CC_LIGHTFOOT_PHASE_DORMANT;
        }
        break;
    case CC_LIGHTFOOT_PHASE_DESPAWN:
        if (state->attachedWeapon != NULL) {
            if (obj->childObjs[0] != NULL) {
                ObjLink_DetachChild(obj, state->attachedWeapon);
            }
            Obj_FreeObject(state->attachedWeapon);
            state->attachedWeapon = 0;
        }
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_UPDATE_DISABLED);
        ObjHits_DisableObject(obj);
        return;
    }
    phase = state->phase;
    if (phase >= CC_LIGHTFOOT_PHASE_GUARD && phase <= CC_LIGHTFOOT_PHASE_RECOVER) {
        if (ObjHits_PollPriorityHitWithCooldown(obj, &gCCLightfootHitCooldown.cooldown, 0, hitPos) != 0) {
            if (getXZDistanceSquared(&obj->anim.worldPosX,
                              &state->playerObject->anim.worldPosX) <
                CC_LIGHTFOOT_HIT_EFFECT_DISTANCE_SQUARED) {
                objfx_spawnHitEmitterAtPos(hitPos, 8, 0xff, 0xff, 0x78);
                objDoHitParticleFx((void*)obj, CC_LIGHTFOOT_HIT_LIGHT_SCALE, hitPos, 4, 0);
            }
            Sfx_PlayFromObject(obj, SFXTRIG_swdtest222);
        }
    } else if (ObjHits_GetPriorityHit(obj, &hitObjectHandle, 0, 0) != 0) {
        move = hitObjectHandle->anim.romDefNo;
        if (move == CC_LIGHTFOOT_HIT_SEQ_COLOR_FADE_A || move == CC_LIGHTFOOT_HIT_SEQ_COLOR_FADE_B) {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
        }
    }
    phase = state->phase;
    {
        u8* phaseAnim = &animTable->phaseFlags[phase];

        moveId = phaseAnim[offsetof(CCLightfootAnimTable, moveIds)];
        if (moveId != obj->anim.currentMove) {
            if ((phaseAnim[0] & CC_LIGHTFOOT_ANIM_FLAG_START_AT_END) != 0) {
                ObjAnim_SetCurrentMove(obj, moveId, CC_LIGHTFOOT_ANIMATION_PROGRESS_END, 0);
            } else {
                ObjAnim_SetCurrentMove(obj, moveId, CC_LIGHTFOOT_ANIMATION_PROGRESS_START, 0);
            }
        }
    }
    if (ObjAnim_AdvanceCurrentMove(obj, animTable->moveSpeeds[state->phase], timeDelta, NULL) != 0) {
        state->flags |= CC_LIGHTFOOT_FLAG_MOVE_COMPLETE;
    } else {
        state->flags &= ~CC_LIGHTFOOT_FLAG_MOVE_COMPLETE;
    }
}

void ccLightfoot_init(GameObject* obj, const CCLightfootPlacement* placement) {
    obj->anim.rotX = (s16)((u32)placement->rotXByte << CC_LIGHTFOOT_ROT_X_SHIFT);
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HIDDEN);
    obj->animEventCallback = ccLightfoot_animationEventCallback;
}
