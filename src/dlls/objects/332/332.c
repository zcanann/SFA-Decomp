/* Baby CloudRunner behavior shared by the CloudRunner object variants. */

#include "dlls/objects/332.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/obj_query.h"
#include "main/object_render.h"
#include "main/object_update_list.h"
#include "main/objhits.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/gameloop_gamebit_api.h"
#include "main/maketex_random_api.h"
#include "main/maketex_timer_api.h"
#include "main/obj_message.h"

#define BABYCLOUDRUNNER_MUTTER_SFX_COUNT 4
#define BABYCLOUDRUNNER_AIR_METER_COUNT  4

#define BABYCLOUDRUNNER_PRIMARY_OBJECT_GROUP   3
#define BABYCLOUDRUNNER_SECONDARY_OBJECT_GROUP 0x20
#define BABYCLOUDRUNNER_AMBIENT_OBJECT_ID      0x788

#define BABYCLOUDRUNNER_AIR_METER_TEXTURE_ID     0x5D1
#define BABYCLOUDRUNNER_MESSAGE_QUEUE_CAPACITY   4
#define BABYCLOUDRUNNER_OBJECT_TYPE_ID           0
#define BABYCLOUDRUNNER_CURVE_MODE               0x19
#define BABYCLOUDRUNNER_MUTTER_SFX_PERIOD        500
#define BABYCLOUDRUNNER_TURN_FRAMES              0x1E
#define BABYCLOUDRUNNER_TURN_ALIGNMENT_TOLERANCE 200
#define BABYCLOUDRUNNER_TURN_YAW_SHIFT           3
#define BABYCLOUDRUNNER_TURN_ANIM_SHIFT          2
#define BABYCLOUDRUNNER_IDLE_ANIM_SPEED          0.0064f
#define BABYCLOUDRUNNER_TURN_ANIM_RATE_DIVISOR   10000.0f

#define BABYCLOUDRUNNER_MOVE_IDLE_A  0
#define BABYCLOUDRUNNER_MOVE_IDLE_B  2
#define BABYCLOUDRUNNER_MOVE_BURROW  5
#define BABYCLOUDRUNNER_MOVE_TURN    9
#define BABYCLOUDRUNNER_MOVE_SURFACE 0xD

#define BABYCLOUDRUNNER_SEQUENCE_AT_ROOST    1
#define BABYCLOUDRUNNER_SEQUENCE_CAPTURED    4
#define BABYCLOUDRUNNER_SEQUENCE_METER_EMPTY 6

#define BABYCLOUDRUNNER_CAPTURE_DURATION       0x3C
#define BABYCLOUDRUNNER_CAPTURE_BEHAVIOUR      0xC
#define BABYCLOUDRUNNER_CAPTURE_SFX_ID         0x296
#define BABYCLOUDRUNNER_CAPTURE_SFX_PITCH      0x1000
#define BABYCLOUDRUNNER_CAPTURE_COUNT_GAME_BIT 0x901
#define BABYCLOUDRUNNER_AIR_METER_GAME_BIT     0x66
#define BABYCLOUDRUNNER_MAX_RUNNER_INDEX       4

#define BABYCLOUDRUNNER_SEQUENCE_EVENT_SFX       1
#define BABYCLOUDRUNNER_HEAD_AIM_LIMIT           0x28
#define BABYCLOUDRUNNER_SEQUENCE_HIT_VOLUME_FLAG 0x02

s16 gBabyCloudRunnerMutterSfxTable[BABYCLOUDRUNNER_MUTTER_SFX_COUNT] = {0xD4, 0xD4, 0x31C, 0x31C};
s16 gBabyCloudRunnerMutterSfxTableSpecial[BABYCLOUDRUNNER_MUTTER_SFX_COUNT] = {0x292, 0x292, 0x292, 0x292};
f32 gBabyCloudRunnerTargetNearDist = 160.0f;
f32 gBabyCloudRunnerPlayerFarDist = 70.0f;
f32 gBabyCloudRunnerHomeMoveSpeed = 2.0f;
f32 gBabyCloudRunnerHomeAnimSpeed = 0.05f;
u8 gBabyCloudRunnerHomeMoveState = 2;
f32 gBabyCloudRunnerVerticalSpeedScale = 0.01f;

int babyCloudRunner_updateBurrowAnimation(GameObject* obj) {
    f32 speed;
    BabyCloudRunnerState* state = obj->extra;
    if (obj->anim.currentMove != BABYCLOUDRUNNER_MOVE_BURROW && obj->anim.currentMove != BABYCLOUDRUNNER_MOVE_SURFACE) {
        ObjAnim_SetCurrentMove(obj, BABYCLOUDRUNNER_MOVE_SURFACE, obj->anim.currentMoveProgress, 0);
    }
    if (obj->anim.currentMove == BABYCLOUDRUNNER_MOVE_BURROW && obj->anim.velocityY > 0.01f) {
        ObjAnim_SetCurrentMove(obj, BABYCLOUDRUNNER_MOVE_SURFACE, obj->anim.currentMoveProgress, 0);
    }
    if (obj->anim.currentMove == BABYCLOUDRUNNER_MOVE_SURFACE && obj->anim.velocityY < 0.0f) {
        ObjAnim_SetCurrentMove(obj, BABYCLOUDRUNNER_MOVE_BURROW, obj->anim.currentMoveProgress, 0);
    }
    speed = obj->anim.velocityY * gBabyCloudRunnerVerticalSpeedScale + 0.07f;
    speed *= 0.5f;
    if (speed < 0.0f) {
        speed = 0.0f;
    }
    if (speed > 0.5f) {
        speed = 0.5f;
    }
    if (obj->anim.currentMove == BABYCLOUDRUNNER_MOVE_SURFACE) {
        if (obj->anim.currentMoveProgress > 0.5f) {
            if (!state->stateFlags.burrowSfxLatched) {
                Sfx_PlayFromObject(obj, SFXTRIG_mn_heart1_c_334);
                state->stateFlags.burrowSfxLatched = 1;
            }
        } else {
            state->stateFlags.burrowSfxLatched = 0;
        }
    }
    ObjAnim_AdvanceCurrentMove(obj, speed, timeDelta, 0);
    return 1;
}

void babyCloudRunner_turnTowardTarget(GameObject* obj, GameObject* target, BabyCloudRunnerState* state, int playMove) {
    s16 yawStep;
    characterAimHeadAtTarget(obj, target, &state->eyeAnimState, BABYCLOUDRUNNER_HEAD_AIM_LIMIT, 0, 3);
    yawStep = Obj_GetYawDeltaToObject(obj, target, 0);
    yawStep >>= BABYCLOUDRUNNER_TURN_YAW_SHIFT;
    obj->anim.rotX += yawStep;
    if (playMove == 0) {
        return;
    }
    if (yawStep > -BABYCLOUDRUNNER_TURN_ALIGNMENT_TOLERANCE &&
        yawStep < BABYCLOUDRUNNER_TURN_ALIGNMENT_TOLERANCE) {
        if (state->turnLatch != 0) {
            state->turnLatch = 0;
            ObjAnim_SetCurrentMove(obj, BABYCLOUDRUNNER_MOVE_IDLE_A, 0.0f, 0);
        } else {
            ObjAnim_AdvanceCurrentMove(obj, BABYCLOUDRUNNER_IDLE_ANIM_SPEED, timeDelta, 0);
        }
    } else {
        if (state->turnLatch == 0) {
            state->turnLatch = 1;
            ObjAnim_SetCurrentMove(obj, BABYCLOUDRUNNER_MOVE_TURN, 0.0f, 0);
        } else {
            int turnAnimStep;
            if (yawStep > 0) {
                turnAnimStep = yawStep >> BABYCLOUDRUNNER_TURN_ANIM_SHIFT;
            } else {
                turnAnimStep = -yawStep >> BABYCLOUDRUNNER_TURN_ANIM_SHIFT;
            }
            ObjAnim_AdvanceCurrentMove(obj, (f32)(s16)turnAnimStep / BABYCLOUDRUNNER_TURN_ANIM_RATE_DIVISOR, timeDelta,
                                       0);
        }
    }
}

int babyCloudRunner_tryCapture(GameObject* object) {
    GameObject* obj;
    int shouldCapture;
    BabyCloudRunnerPlacement* rangePlacement;
    BabyCloudRunnerState* state;
    BabyCloudRunnerPlacement* gameBitPlacement;
    GameObject* player;
    /* Preserve the generic-pointer aliasing shape of the descriptor callback. */
    obj = (void*)object;
    state = obj->extra;
    gameBitPlacement = (BabyCloudRunnerPlacement*)obj->anim.placement;
    player = Obj_GetPlayerObject();
    rangePlacement = (BabyCloudRunnerPlacement*)obj->anim.placement;
    shouldCapture = 0;
    if (Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX) < (f32)(s16)rangePlacement->innerRadius) {
        if (state->runnerState == BABYCLOUDRUNNER_STATE_FREED) {
            if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                shouldCapture = 1;
            }
        }
    }
    if (shouldCapture != 0) {
        s16toFloat(&state->captureTimer, BABYCLOUDRUNNER_CAPTURE_DURATION);
        obj->userData1 = 1;
        obj->anim.rotX = state->roostYaw;
        (*gObjectTriggerInterface)->runSequence(BABYCLOUDRUNNER_SEQUENCE_CAPTURED, obj, -1);
        state->captureTimer = 3.0f;
        gameBitIncrement(BABYCLOUDRUNNER_CAPTURE_COUNT_GAME_BIT);
        state->behaviourState = BABYCLOUDRUNNER_CAPTURE_BEHAVIOUR;
        mainSetBits(gameBitPlacement->enableGameBit, 1);
        obj->userData1 = 0;
        return 1;
    }
    objSoundStartTimed(obj, &state->soundState, BABYCLOUDRUNNER_CAPTURE_SFX_ID, BABYCLOUDRUNNER_CAPTURE_SFX_PITCH, -1,
                       1);
    Sfx_PlayFromObject(obj, SFXTRIG_wp_ice_freeze);
    return 0;
}

int babyCloudRunner_func0A(GameObject* obj) {
    BabyCloudRunnerState* state = obj->extra;
    return !(state->captureFlags & BABYCLOUDRUNNER_CAPTURE_ACTIVE);
}

int gBabyCloudRunnerAirMeterValues[BABYCLOUDRUNNER_AIR_METER_COUNT] = {0x1770, 0x2EE0, 0x2EE0, 0x3E80};

ObjectDescriptor12 gBabyCloudRunnerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)babyCloudRunner_initialise,
    (ObjectDescriptorCallback)babyCloudRunner_release,
    0,
    (ObjectDescriptorCallback)babyCloudRunner_init,
    (ObjectDescriptorCallback)babyCloudRunner_update,
    (ObjectDescriptorCallback)babyCloudRunner_hitDetect,
    (ObjectDescriptorCallback)babyCloudRunner_render,
    (ObjectDescriptorCallback)babyCloudRunner_free,
    (ObjectDescriptorCallback)babyCloudRunner_getObjectTypeId,
    babyCloudRunner_getExtraSize,
    (ObjectDescriptorCallback)babyCloudRunner_func0A,
    (ObjectDescriptorCallback)babyCloudRunner_tryCapture,
};

int babyCloudRunner_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    GameObject* player;
    BabyCloudRunnerPlacement* placement = (BabyCloudRunnerPlacement*)obj->anim.placement;
    s8 inRange;
    s16 yaw;
    int halfInner;
    f32 dx;
    f32 dz;
    f32 distanceSquared;
    BabyCloudRunnerState* state = obj->extra;
    if (obj->seqIndex == BABYCLOUDRUNNER_SEQUENCE_CAPTURED) {
        return 0;
    }
    animUpdate->movementState = 0;
    player = Obj_GetPlayerObject();
    dx = player->anim.localPosX - placement->base.posX;
    dz = player->anim.localPosZ - placement->base.posZ;
    distanceSquared = dx * dx + dz * dz;
    if (distanceSquared < (f32)((halfInner = placement->innerRadius / 2) * halfInner)) {
        inRange = 1;
    } else {
        inRange = 0;
    }
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    {
        int found;
        BabyCloudRunnerPlacement* interactionPlacement;
        BabyCloudRunnerState* interactionState = obj->extra;
        GameObject* interactionPlayer = Obj_GetPlayerObject();
        interactionPlacement = (BabyCloudRunnerPlacement*)obj->anim.placement;
        found = 0;
        if (Vec_distance(&interactionPlayer->anim.worldPosX, &obj->anim.worldPosX) <
                (f32)interactionPlacement->innerRadius &&
            interactionState->runnerState == BABYCLOUDRUNNER_STATE_FREED &&
            (obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
            found = 1;
        }
        if (found != 0) {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        } else {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
    if (inRange == 0 && state->runnerState == BABYCLOUDRUNNER_STATE_CHASED) {
        f32 radius = (f32)placement->outerRadius;
        if (objGetNearestTypeTo(BABYCLOUDRUNNER_PRIMARY_OBJECT_GROUP, obj, &radius) != NULL) {
            inRange = 1;
        }
    }
    {
        s8 eventIndex;
        for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
            if (animUpdate->eventIds[eventIndex] == BABYCLOUDRUNNER_SEQUENCE_EVENT_SFX) {
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
        }
    }
    state->behaviourState = 0;
    switch (state->behaviourState) {
    case 10:
    case 11:
        if (state->linkedObject != NULL) {
            state->scale *= 0.995f;
            state->linkedObject->anim.rootMotionScale = state->scale;
        }
        state->behaviourState = 0xb;
        if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < (f32)placement->innerRadius &&
            (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            state->behaviourState = 7;
            return BABYCLOUDRUNNER_SEQUENCE_CAPTURED;
        }
        break;
    case 0:
    case 8:
        animUpdate->flags &= ~BABYCLOUDRUNNER_SEQUENCE_HIT_VOLUME_FLAG;
        yaw = Obj_GetYawDeltaToObject(obj, player, 0);
        characterAimHeadAtTarget(obj, player, &state->eyeAnimState, BABYCLOUDRUNNER_HEAD_AIM_LIMIT, 0, 3);
        obj->anim.rotX += yaw / 8;
        if (inRange != 0) {
            animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
        } else {
            animUpdate->sequenceControlFlags = OBJSEQ_CONTROL_CLEAR_LATCH_A;
        }
        break;
    case 5:
        animUpdate->flags &= ~BABYCLOUDRUNNER_SEQUENCE_HIT_VOLUME_FLAG;
        yaw = Obj_GetYawDeltaToObject(obj, (GameObject*)getTrickyObject(), 0);
        characterAimHeadAtTarget(obj, getTrickyObject(), &state->eyeAnimState, BABYCLOUDRUNNER_HEAD_AIM_LIMIT, 0, 3);
        obj->anim.rotX += yaw / 8;
        break;
    }
    return 0;
}

int babyCloudRunner_getExtraSize(void) {
    return sizeof(BabyCloudRunnerState);
}

int babyCloudRunner_getObjectTypeId(void) {
    return BABYCLOUDRUNNER_OBJECT_TYPE_ID;
}

void babyCloudRunner_free(GameObject* obj) {
    objFreeObjectType(obj, BABYCLOUDRUNNER_SECONDARY_OBJECT_GROUP);
    objFreeObjectType(obj, BABYCLOUDRUNNER_PRIMARY_OBJECT_GROUP);
}

void babyCloudRunner_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    s32 isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void babyCloudRunner_hitDetect(void) {
}

void babyCloudRunner_update(GameObject* obj) {
    GameObject* player;
    BabyCloudRunnerState* state;
    BabyCloudRunnerPlacement* placement;
    int found;
    BabyCloudRunnerPlacement* interactionPlacement;
    BabyCloudRunnerState* interactionState;
    GameObject* nearbyObject;
    int inRange;
    MoveLibTarget target;
    int curveMode;
    f32 radius;
    placement = (BabyCloudRunnerPlacement*)obj->anim.placement;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    getTrickyObject();
    if (mainGetBit(placement->runnerGameBit) != 0) {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        state->captureFlags &= ~BABYCLOUDRUNNER_CAPTURE_ACTIVE;
        Obj_RemoveFromUpdateList(obj);
        objFreeObjectType(obj, BABYCLOUDRUNNER_SECONDARY_OBJECT_GROUP);
        objFreeObjectType(obj, BABYCLOUDRUNNER_PRIMARY_OBJECT_GROUP);
    }
    if (state->runnerState == BABYCLOUDRUNNER_STATE_CHASED && mainGetBit(BABYCLOUDRUNNER_AIR_METER_GAME_BIT) != 0) {
        (*gObjectTriggerInterface)->runSequence(BABYCLOUDRUNNER_SEQUENCE_METER_EMPTY, obj, -1);
        (*gGameUIInterface)->airMeterShutdown();
    } else if (timerIsActive(&state->captureTimer) != 0) {
        state->captureFlags |= BABYCLOUDRUNNER_CAPTURE_ACTIVE;
        state->behaviourState = 0;
        if (obj->userData1 < 0) {
            if (placement->runnerGameBit != -1) {
                mainSetBits(placement->runnerGameBit, 1);
            }
            ObjHits_DisableObject(obj);
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            state->captureFlags &= ~BABYCLOUDRUNNER_CAPTURE_ACTIVE;
            Obj_RemoveFromUpdateList(obj);
            objFreeObjectType(obj, BABYCLOUDRUNNER_SECONDARY_OBJECT_GROUP);
            objFreeObjectType(obj, BABYCLOUDRUNNER_PRIMARY_OBJECT_GROUP);
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        } else {
            obj->userData1 = obj->userData1 - 1;
        }
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (state->runnerState == BABYCLOUDRUNNER_STATE_FIND_CURVE) {
            curveMode = BABYCLOUDRUNNER_CURVE_MODE;
            if ((*gRomCurveInterface)->initCurve(&state->curveWalker, obj, 200.0f, &curveMode, 0) == 0) {
                state->runnerState = BABYCLOUDRUNNER_STATE_FOLLOW_CURVE;
                storeZeroToFloatParam(&state->countdownTimer);
            }
        } else {
            if (randomChanceOneIn(BABYCLOUDRUNNER_MUTTER_SFX_PERIOD) != 0) {
                u16 sfxId = state->mutterSfxTable[randomGetRange(0, BABYCLOUDRUNNER_MUTTER_SFX_COUNT - 1)];
                objSoundStart(obj, &state->soundState, sfxId);
            }
            objSoundUpdateMouth(obj, &state->soundState);
            if (state->runnerState == BABYCLOUDRUNNER_STATE_FOLLOW_CURVE ||
                state->runnerState == BABYCLOUDRUNNER_STATE_CHASED) {
                f32 speed = state->curveSpeed;
                Obj_UpdateRomCurveFollowVelocity(obj, &state->curveWalker, speed, 10.0f * speed, 5.0f * speed, 1);
                Obj_SmoothTurnAnglesTowardVelocity(obj, &obj->anim.velocity, BABYCLOUDRUNNER_TURN_FRAMES, 10.0f, 0.2f);
                objMove(obj, obj->anim.velocityX, obj->anim.velocityY, obj->anim.velocityZ);
                if (state->runnerState == BABYCLOUDRUNNER_STATE_FOLLOW_CURVE) {
                    if (state->runnerIndex != -1 && mainGetBit(state->runnerIndex + GAMEBIT_CFRelated0B2A) != 0) {
                        state->runnerState = BABYCLOUDRUNNER_STATE_CHASED;
                        mainSetBits(BABYCLOUDRUNNER_AIR_METER_GAME_BIT, 0);
                        (*gGameUIInterface)
                            ->initAirMeter(gBabyCloudRunnerAirMeterValues[state->runnerIndex],
                                           BABYCLOUDRUNNER_AIR_METER_TEXTURE_ID);
                        s16toFloat(&state->countdownTimer, (s16)gBabyCloudRunnerAirMeterValues[state->runnerIndex]);
                    }
                    babyCloudRunner_updateBurrowAnimation(obj);
                    return;
                }
                if (state->runnerState == BABYCLOUDRUNNER_STATE_CHASED) {
                    nearbyObject = objGetNearestTypeTo(BABYCLOUDRUNNER_PRIMARY_OBJECT_GROUP, obj, 0);
                    if (nearbyObject != NULL && Vec_distance(&nearbyObject->anim.worldPosX, &state->handoffPosition.x) <
                                                    gBabyCloudRunnerTargetNearDist) {
                        babyCloudRunner_turnTowardTarget(obj, nearbyObject, state, 0);
                        if (Vec_distance(&Obj_GetPlayerObject()->anim.worldPosX, &nearbyObject->anim.worldPosX) >
                            gBabyCloudRunnerPlayerFarDist) {
                            enemy_setTrackedObj(nearbyObject, obj);
                            if (obj->anim.currentMove != BABYCLOUDRUNNER_MOVE_SURFACE) {
                                ObjAnim_SetCurrentMove(obj, BABYCLOUDRUNNER_MOVE_SURFACE, obj->anim.currentMoveProgress,
                                                       0);
                            }
                            ObjAnim_AdvanceCurrentMove(obj, 0.01f, timeDelta, 0);
                        } else {
                            enemy_setTrackedObj(nearbyObject, Obj_GetPlayerObject());
                        }
                    } else {
                        if (nearbyObject != NULL) {
                            enemy_setTrackedObj(nearbyObject, Obj_GetPlayerObject());
                        }
                    }
                    babyCloudRunner_updateBurrowAnimation(obj);
                }
            }
            inRange = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < (f32)(placement->innerRadius / 2);
            if (state->runnerState == BABYCLOUDRUNNER_STATE_CHASED) {
                radius = (f32)placement->outerRadius;
                if (timerIsActive(&state->countdownTimer) != 0) {
                    if ((Obj_GetPlayerObject()->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0 &&
                        timerCountDown(&state->countdownTimer) != 0) {
                        (*gObjectTriggerInterface)->runSequence(BABYCLOUDRUNNER_SEQUENCE_METER_EMPTY, obj, -1);
                        (*gGameUIInterface)->airMeterShutdown();
                        return;
                    }
                    (*gGameUIInterface)->runAirMeter((int)state->countdownTimer);
                }
                if (inRange == 0 && objGetNearestTypeTo(BABYCLOUDRUNNER_PRIMARY_OBJECT_GROUP, obj, &radius) != NULL) {
                    inRange = 1;
                }
                if (mainGetBit(state->runnerIndex + GAMEBIT_CFRelated0B2E) != 0) {
                    state->runnerState = BABYCLOUDRUNNER_STATE_FREED;
                    (*gGameUIInterface)->airMeterShutdown();
                    Sfx_PlayFromObject(obj, SFXTRIG_menuups16k);
                    storeZeroToFloatParam(&state->countdownTimer);
                }
            } else {
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                interactionState = obj->extra;
                {
                    GameObject* interactionPlayer = Obj_GetPlayerObject();
                    interactionPlacement = (BabyCloudRunnerPlacement*)obj->anim.placement;
                    found = 0;
                    if (Vec_distance(&interactionPlayer->anim.worldPosX, &obj->anim.worldPosX) <
                            (f32)interactionPlacement->innerRadius &&
                        interactionState->runnerState == BABYCLOUDRUNNER_STATE_FREED &&
                        (obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                        found = 1;
                    }
                }
                if (found != 0) {
                    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
                } else {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
            }
            if (state->runnerState == BABYCLOUDRUNNER_STATE_FREED) {
                if (!state->stateFlags.atRoost) {
                    target.x = placement->base.posX;
                    target.y = placement->base.posY;
                    target.z = placement->base.posZ;
                    target.angle = state->roostYaw;
                    target.angleY = 0;
                    target.angleZ = 0;
                    obj->anim.rotY = 0;
                    obj->anim.rotZ = 0;
                    if (dll_2E_moveToTarget(obj, &target, gBabyCloudRunnerHomeMoveSpeed, -1,
                                            &gBabyCloudRunnerHomeAnimSpeed, &gBabyCloudRunnerHomeMoveState) != 0) {
                        state->stateFlags.atRoost = 1;
                        mainSetBits(BABYCLOUDRUNNER_AIR_METER_GAME_BIT, 0);
                    }
                    ObjAnim_AdvanceCurrentMove(obj, gBabyCloudRunnerHomeAnimSpeed, timeDelta, 0);
                } else {
                    if (inRange != 0) {
                        (*gObjectTriggerInterface)->runSequence(BABYCLOUDRUNNER_SEQUENCE_AT_ROOST, obj, -1);
                        state->unknown0B0 = 1;
                    }
                    babyCloudRunner_turnTowardTarget(obj, Obj_GetPlayerObject(), state, 1);
                    if (ObjAnim_AdvanceCurrentMove(obj, state->animSpeed, timeDelta, 0) != 0) {
                        if (randomChanceOneIn(2) != 0) {
                            ObjAnim_SetCurrentMove(obj, BABYCLOUDRUNNER_MOVE_IDLE_B, 0.0f, 0);
                        } else {
                            ObjAnim_SetCurrentMove(obj, BABYCLOUDRUNNER_MOVE_IDLE_A, 0.0f, 0);
                        }
                    }
                }
            }
        }
    }
}

void babyCloudRunner_init(GameObject* obj, BabyCloudRunnerPlacement* placement) {
    BabyCloudRunnerState* state;

    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, BABYCLOUDRUNNER_MESSAGE_QUEUE_CAPACITY);
    obj->animEventCallback = babyCloudRunner_sequenceCallback;
    obj->anim.rotX = (s16)(placement->initialYaw << 8);
    objAddObjectType(obj, BABYCLOUDRUNNER_PRIMARY_OBJECT_GROUP);
    state = obj->extra;
    state->unknown0B0 = 0;
    state->unknown0B4 = 0;
    state->unknown0B8 = 0;
    state->unknown0BC = 0;
    state->turnLatch = 0;
    state->behaviourState = placement->initialBehaviourState;
    state->unknown0CC = 0;
    storeZeroToFloatParam(&state->captureTimer);
    state->linkedObject = NULL;
    state->roostYaw = obj->anim.rotX;
    state->captureFlags = 0;
    state->animSpeed = 0.01f;
    state->runnerState = BABYCLOUDRUNNER_STATE_FIND_CURVE;
    if (mainGetBit(placement->runnerGameBit) != 0) {
        ObjHits_DisableObject(obj);
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        state->captureFlags = state->captureFlags & ~BABYCLOUDRUNNER_CAPTURE_ACTIVE;
        Obj_RemoveFromUpdateList(obj);
        objFreeObjectType(obj, BABYCLOUDRUNNER_PRIMARY_OBJECT_GROUP);
    } else {
        state->runnerIndex = placement->runnerGameBit - GAMEBIT_CFRelated02FC;
        if (obj->anim.romDefNo == BABYCLOUDRUNNER_AMBIENT_OBJECT_ID) {
            state->runnerIndex = -1;
            state->curveSpeed = 3.0f;
            state->mutterSfxTable = gBabyCloudRunnerMutterSfxTableSpecial;
        } else {
            if (state->runnerIndex < 0 || state->runnerIndex > BABYCLOUDRUNNER_MAX_RUNNER_INDEX) {
                state->runnerState = BABYCLOUDRUNNER_STATE_FREED;
            }
            state->curveSpeed = 2.0f;
            state->mutterSfxTable = gBabyCloudRunnerMutterSfxTable;
            objAddObjectType(obj, BABYCLOUDRUNNER_SECONDARY_OBJECT_GROUP);
        }
        state->stateFlags.atRoost = 0;
    }
}

void babyCloudRunner_release(void) {
}

void babyCloudRunner_initialise(void) {
}
