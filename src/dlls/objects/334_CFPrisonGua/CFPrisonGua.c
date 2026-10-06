/* CloudRunner Fortress prison-guard behavior. */

#include "dlls/objects/334_CFPrisonGua.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/dll/waterfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/obj_message.h"
#include "main/object_render.h"
#include "main/object_update_list.h"
#include "main/objhits.h"
#include "main/objprint_character_api.h"
#include "main/objseq.h"
#include "main/render_lactions_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define CFPRISONGUARD_OBJECT_TYPE_ID         0x49
#define CFPRISONGUARD_MESSAGE_QUEUE_CAPACITY 4
#define CFPRISONGUARD_HIT_PRIORITY           19
#define CFPRISONGUARD_PLAYER_CAUGHT_TIMER    0x14
#define CFPRISONGUARD_PLAYER_CAUGHT_ANIM     0x40
#define CFPRISONGUARD_LACTION_ID             0x18

#define CFPRISONGUARD_SEQUENCE_IDLE          0
#define CFPRISONGUARD_SEQUENCE_ALERT         1
#define CFPRISONGUARD_SEQUENCE_PLAYER_CAUGHT 2
#define CFPRISONGUARD_SEQUENCE_TRANSITION    4

#define CFPRISONGUARD_TRIGGER_LACTION          1
#define CFPRISONGUARD_TRIGGER_SEQUENCE_DONE    4
#define CFPRISONGUARD_TRIGGER_ALARM_RAMP       5
#define CFPRISONGUARD_TRIGGER_ALARM_RAMP_RESET 0x29

#define CFPRISONGUARD_WATER_MOVE_A      0x2E
#define CFPRISONGUARD_WATER_MOVE_B      0x103
#define CFPRISONGUARD_WATER_SFX_CHANNEL 0x10

#define CFPRISONGUARD_ALARM_PARTICLE_EFFECT 3
#define CFPRISONGUARD_ALARM_PARTICLE_LIMIT  1.5f


ObjectDescriptor gCFPrisonGuardObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cfPrisonGuard_initialise,
    (ObjectDescriptorCallback)cfPrisonGuard_release,
    0,
    (ObjectDescriptorCallback)cfPrisonGuard_init,
    (ObjectDescriptorCallback)cfPrisonGuard_update,
    (ObjectDescriptorCallback)cfPrisonGuard_hitDetect,
    (ObjectDescriptorCallback)cfPrisonGuard_render,
    (ObjectDescriptorCallback)cfPrisonGuard_free,
    (ObjectDescriptorCallback)cfPrisonGuard_getObjectTypeId,
    cfPrisonGuard_getExtraSize,
};

int cfPrisonGuard_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    GameObject* player;
    CfPrisonGuardState* state = obj->extra;
    s8 uncleFlewOff;
    s8 guardianFreed;
    s8 shouldTransition;
    f32 distance;
    GameObject* messageSender;
    u32 message;
    void* messageArgument = 0;
    CfPrisonGuardPlacement* placement = (CfPrisonGuardPlacement*)obj->anim.placement;

    switch (animUpdate->curEventId) {
    case CFPRISONGUARD_TRIGGER_ALARM_RAMP_RESET:
        state->alarmRamp = 0.0f;
        break;
    case CFPRISONGUARD_TRIGGER_SEQUENCE_DONE:
        state->stateId = CFPRISONGUARD_STATE_SEQUENCE_COMPLETE;
        return 0;
    case CFPRISONGUARD_TRIGGER_ALARM_RAMP:
        state->alarmRamp = 0.01f * framesThisStep + state->alarmRamp;
        break;
    }
    if (obj->seqIndex < 0) {
        return 0;
    }
    ObjHits_EnableObject(obj);
    uncleFlewOff = mainGetBit(GAMEBIT_CF_UncleFlewOff);
    guardianFreed = mainGetBit(GAMEBIT_CF_GuardianFreed);
    if ((state->sequenceFlags & CFPRISONGUARD_SEQUENCE_FLAG_WAITING_FOR_PERCH) != 0 &&
        mainGetBit(GAMEBIT_CF_PrisonCageOpened) != 0) {
        state->sequenceFlags &= ~CFPRISONGUARD_SEQUENCE_FLAG_WAITING_FOR_PERCH;
        return CFPRISONGUARD_SEQUENCE_TRANSITION;
    }
    if (uncleFlewOff != 0) {
        return CFPRISONGUARD_SEQUENCE_TRANSITION;
    }
    if (uncleFlewOff != 0 || state->stateId == CFPRISONGUARD_STATE_PLAYER_CAUGHT) {
        state->stateId = CFPRISONGUARD_STATE_PLAYER_CAUGHT;
        return 0;
    }
    shouldTransition = 0;
    player = Obj_GetPlayerObject();
    switch (state->stateId) {
    case CFPRISONGUARD_STATE_IDLE:
        characterCloseEyes(obj, &state->eyeAnimState);
        distance = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
        if (guardianFreed == 0) {
            if (distance < (f32)placement->watchRadius ||
                waterfx_consumePendingImpactNearPoint(&obj->anim.localPosX, 600.0f) != 0) {
                if (objGetAnimState80A(player) != CFPRISONGUARD_PLAYER_CAUGHT_ANIM) {
                    shouldTransition = 1;
                    state->stateId = CFPRISONGUARD_STATE_ALERT;
                } else {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                    state->stateId = CFPRISONGUARD_STATE_PLAYER_CAUGHT;
                    state->stateTimer = CFPRISONGUARD_PLAYER_CAUGHT_TIMER;
                    (*gObjectTriggerInterface)->runSequence(CFPRISONGUARD_SEQUENCE_PLAYER_CAUGHT, obj, -1);
                    return CFPRISONGUARD_SEQUENCE_TRANSITION;
                }
            }
        }
        break;
    case CFPRISONGUARD_STATE_WATCH_DELAY:
        if ((state->stateTimer -= framesThisStep) <= 0) {
            state->stateId = CFPRISONGUARD_STATE_WATCHING;
        }
        characterCloseEyes(obj, &state->eyeAnimState);
        break;
    case CFPRISONGUARD_STATE_WATCHING:
        distance = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
        if (guardianFreed == 0) {
            if (distance < (f32)placement->watchRadius) {
                if (objGetAnimState80A(player) != CFPRISONGUARD_PLAYER_CAUGHT_ANIM) {
                    shouldTransition = 1;
                    state->stateId = CFPRISONGUARD_STATE_ALERT;
                } else {
                    state->stateId = CFPRISONGUARD_STATE_WATCH_DELAY;
                }
            }
        }
        break;
    case CFPRISONGUARD_STATE_IDLE_DELAY:
        if ((state->stateTimer -= framesThisStep) <= 0) {
            state->stateId = CFPRISONGUARD_STATE_IDLE;
        }
        break;
    case CFPRISONGUARD_STATE_PLAYER_CAUGHT:
        return 0;
    case CFPRISONGUARD_STATE_SEQUENCE_COMPLETE:
        return 0;
    case CFPRISONGUARD_STATE_HIT:
        shouldTransition = 1;
        state->stateId = CFPRISONGUARD_STATE_ALERT;
        break;
    }
    if (obj->anim.currentMove == CFPRISONGUARD_WATER_MOVE_B || obj->anim.currentMove == CFPRISONGUARD_WATER_MOVE_A) {
        Sfx_PlayFromObject(obj, SFXTRIG_foot_water_roll);
    } else {
        Sfx_StopObjectChannel(obj, CFPRISONGUARD_WATER_SFX_CHANNEL);
    }
    if (uncleFlewOff != 0 && state->uncleFlewOffLatch == 0) {
        shouldTransition = 1;
    }
    if (shouldTransition != 0) {
        return CFPRISONGUARD_SEQUENCE_TRANSITION;
    }
    state->uncleFlewOffLatch = uncleFlewOff;
    animUpdate->movementState = 0;
    while (ObjMsg_Pop(obj, &message, &messageSender, &messageArgument) != 0) {
    }
    if (animUpdate->curEventId == CFPRISONGUARD_TRIGGER_LACTION) {
        getLActions(obj, obj, CFPRISONGUARD_LACTION_ID, 0, 0, 0);
        animUpdate->curEventId = 0;
    }
    return 0;
}

int cfPrisonGuard_getExtraSize(void) {
    return sizeof(CfPrisonGuardState);
}

int cfPrisonGuard_getObjectTypeId(void) {
    return CFPRISONGUARD_OBJECT_TYPE_ID;
}

void cfPrisonGuard_free(void) {
}

void cfPrisonGuard_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    CfPrisonGuardState* state = obj->extra;
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
    if (visible != 0) {
        f32 alarmRamp = state->alarmRamp;
        if (alarmRamp > 0.0f) {
            state->alarmRamp = 0.01f * (f32)(u32)framesThisStep + alarmRamp;
            if (state->alarmRamp < CFPRISONGUARD_ALARM_PARTICLE_LIMIT) {
                objDoParticleFx(obj, 1.0f, CFPRISONGUARD_ALARM_PARTICLE_EFFECT, state->alarmRamp, NULL);
            }
        }
    }
}

void cfPrisonGuard_hitDetect(GameObject* obj) {
    CfPrisonGuardState* state = obj->extra;
    if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) == CFPRISONGUARD_HIT_PRIORITY) {
        state->stateId = CFPRISONGUARD_STATE_HIT;
    }
}

void cfPrisonGuard_update(GameObject* obj) {
    CfPrisonGuardState* state;
    GameObject* player;
    CfPrisonGuardPlacement* placement;
    int hasPrisonKey;
    f32 distance;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    placement = (CfPrisonGuardPlacement*)obj->anim.placement;
    if (state->statusFlags.initialUpdate) {
        state->statusFlags.initialUpdate = 0;
    }
    if (mainGetBit(placement->disableGameBit) != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
        Obj_RemoveFromUpdateList(obj);
        return;
    }
    hasPrisonKey = mainGetBit(GAMEBIT_ITEM_PrisonKey_Got);
    distance = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
    if (state->sequenceFlags == CFPRISONGUARD_SEQUENCE_FLAG_INITIAL_PENDING) {
        waterfx_consumePendingImpactNearPoint(&obj->anim.localPosX, 600.0f);
        (*gObjectTriggerInterface)->runSequence(CFPRISONGUARD_SEQUENCE_IDLE, obj, -1);
        state->sequenceFlags = CFPRISONGUARD_SEQUENCE_FLAG_WAITING_FOR_PERCH;
    }
    if (hasPrisonKey == 0) {
        if (state->stateId != CFPRISONGUARD_STATE_ALERT) {
            if (!(distance < (f32)(s32)placement->watchRadius) &&
                waterfx_consumePendingImpactNearPoint(&obj->anim.localPosX, 600.0f) == 0) {
                return;
            }
        }
        if (objGetAnimState80A(player) != CFPRISONGUARD_PLAYER_CAUGHT_ANIM) {
            (*gObjectTriggerInterface)->runSequence(CFPRISONGUARD_SEQUENCE_ALERT, obj, -1);
        }
    }
}

void cfPrisonGuard_init(GameObject* obj, CfPrisonGuardPlacement* placement) {
    CfPrisonGuardState* state = obj->extra;
    state->sequenceFlags = CFPRISONGUARD_SEQUENCE_FLAG_INITIAL_PENDING;
    obj->anim.rotX = (s16)(placement->initialYaw << 8);
    obj->animEventCallback = cfPrisonGuard_sequenceCallback;
    ObjMsg_AllocQueue(obj, CFPRISONGUARD_MESSAGE_QUEUE_CAPACITY);
    state->uncleFlewOffLatch = 1;
    if (mainGetBit(GAMEBIT_CF_PrisonCageOpened) != 0) {
        state->sequenceFlags |= CFPRISONGUARD_SEQUENCE_FLAG_PERCH_ACTIVE;
    }
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    state->statusFlags.initialUpdate = 1;
}

void cfPrisonGuard_release(void) {
}

void cfPrisonGuard_initialise(void) {
}
