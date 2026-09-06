/*
 * DBSH_Shrine (DLL 0x195) - Krazoa Shrine Test of Strength.
 *
 * Runs the floating shrine model, its activation sequence, and the state
 * transitions that award the Krazoa Spirit and reset the test.
 */
#include "dlls/objects/405_DBSH_Shrine.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/game_timer_control_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/map_load.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/objseq.h"
#include "main/pi_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/sky_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define DBSH_SHRINE_OBJ_GROUP 0xB

#define DBSH_SHRINE_REWARD_MAP_ID  0xB
#define DBSH_SHRINE_REWARD_MAP_ACT 3

#define DBSH_SHRINE_ORBIT_RATE_A         512.0f
#define DBSH_SHRINE_ORBIT_RATE_B         128.0f
#define DBSH_SHRINE_ORBIT_RATE_C         192.0f
#define DBSH_SHRINE_ORBIT_HEIGHT         20.0f
#define DBSH_SHRINE_ORBIT_ROTATION_SCALE 600.0f
#define DBSH_SHRINE_ANIMATION_STEP       0.005f
#define DBSH_SHRINE_TURN_RATE_DIVISOR    12.0f
#define DBSH_SHRINE_FADE_DISTANCE        30.0f
#define DBSH_SHRINE_FULL_ALPHA           255.0f
#define DBSH_SHRINE_ORBIT_PI             3.1415927f
#define DBSH_SHRINE_ORBIT_ANGLE_SCALE    32768.0f
#define DBSH_SHRINE_ANGLE_HALF_TURN      0x8000
#define DBSH_SHRINE_ANGLE_WRAP           0xFFFF

#define DBSH_SHRINE_PLAYER_ANIM_STATE_FLAG 2
#define DBSH_SHRINE_MESSAGE_QUEUE_CAPACITY 4
#define DBSH_SHRINE_TRANSITION_ROTATION    0x7FFF

#define DBSH_SHRINE_GAMEBIT_015F     0x15F
#define DBSH_SHRINE_GAMEBIT_0C72     0xC72
#define DBSH_SHRINE_GAMEBIT_0C73     0xC73
#define DBSH_SHRINE_GAMEBIT_APPROACH 0xDD3
#define DBSH_SHRINE_GAMEBIT_0F08     0xF08

#define DBSH_SHRINE_ENVFX_A 0xD4
#define DBSH_SHRINE_ENVFX_B 0xD5
#define DBSH_SHRINE_ENVFX_C 0x222

#define DBSH_SHRINE_UNLOCK_LEVEL       0
#define DBSH_SHRINE_LOCK_MAP_DIR_INDEX 10

enum {
    DBSH_SHRINE_ANIM_EVENT_ACTIVATE = 3,
    DBSH_SHRINE_ANIM_EVENT_GRANT_SPIRIT = 7,
    DBSH_SHRINE_ANIM_EVENT_LOCK_POSE = 14,
    DBSH_SHRINE_ANIM_EVENT_UNLOCK_POSE = 15,
};

typedef enum DBSHShrinePhase {
    DBSH_SHRINE_PHASE_WAITING = 0,
    DBSH_SHRINE_PHASE_RISING = 1,
    DBSH_SHRINE_PHASE_ACTIVE = 2,
    DBSH_SHRINE_PHASE_CLOSING = 4,
    DBSH_SHRINE_PHASE_RESET = 5,
} DBSHShrinePhase;

void dbshShrine_updateHoverMotion(GameObject* obj) {
    const DBSHShrinePlacement* placement;
    DBSHShrineState* state;
    GameObject* player;
    f32 trigA;
    f32 trigB;
    f32 distance;
    s32 angleDelta;
    ObjAnimEventList animEvents;

    placement = (const DBSHShrinePlacement*)obj->anim.placementData;
    state = obj->extra;
    player = Obj_GetPlayerObject();

    if ((obj->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
        obj->anim.rotX = 0;
        obj->anim.localPosY = placement->base.posY;
        return;
    }

    state->orbitPhaseA += (s32)(DBSH_SHRINE_ORBIT_RATE_A * timeDelta);
    state->orbitPhaseB += (s32)(DBSH_SHRINE_ORBIT_RATE_B * timeDelta);
    state->orbitPhaseC += (s32)(DBSH_SHRINE_ORBIT_RATE_C * timeDelta);

    obj->anim.localPosY =
        DBSH_SHRINE_ORBIT_HEIGHT +
        (placement->base.posY + mathSinf((DBSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / DBSH_SHRINE_ORBIT_ANGLE_SCALE));

    trigA = mathSinf((DBSH_SHRINE_ORBIT_PI * state->orbitPhaseB) / DBSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = mathSinf((DBSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / DBSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB += trigA;
    obj->anim.rotZ = (s16)(DBSH_SHRINE_ORBIT_ROTATION_SCALE * trigB);

    trigA = mathSinf((DBSH_SHRINE_ORBIT_PI * state->orbitPhaseC) / DBSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = mathSinf((DBSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / DBSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB += trigA;
    obj->anim.rotY = (s16)(DBSH_SHRINE_ORBIT_ROTATION_SCALE * trigB);

    ObjAnim_AdvanceCurrentMove(obj, DBSH_SHRINE_ANIMATION_STEP, timeDelta, &animEvents);

    if (player == NULL) {
        return;
    }

    angleDelta =
        (u16)getAngle(obj->anim.worldPosX - player->anim.worldPosX, obj->anim.worldPosZ - player->anim.worldPosZ) -
        (u16)obj->anim.rotX;
    if (angleDelta > DBSH_SHRINE_ANGLE_HALF_TURN) {
        angleDelta -= DBSH_SHRINE_ANGLE_WRAP;
    }
    if (angleDelta < -DBSH_SHRINE_ANGLE_HALF_TURN) {
        angleDelta += DBSH_SHRINE_ANGLE_WRAP;
    }
    obj->anim.rotX =
        (s16)(*(s16*)(int)&obj->anim.rotX + (s32)(((f32)angleDelta * timeDelta) / DBSH_SHRINE_TURN_RATE_DIVISOR));

    distance = Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX);
    if (distance <= DBSH_SHRINE_FADE_DISTANCE) {
        obj->anim.alpha = (u8)(s32)(DBSH_SHRINE_FULL_ALPHA * (distance / DBSH_SHRINE_FADE_DISTANCE));
    } else {
        obj->anim.alpha = 0xFF;
    }
}

int dbshShrine_processAnimEvents(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    DBSHShrineState* state = obj->extra;
    GameObject* player;
    int i;
    u8 event;

    (void)unused;
    player = Obj_GetPlayerObject();
    animUpdate->savedFlags = -1;
    animUpdate->movementState = 0;

    for (i = 0; i < animUpdate->eventCount; i++) {
        event = animUpdate->eventIds[i];
        if (event != 0) {
            switch (event) {
            case DBSH_SHRINE_ANIM_EVENT_ACTIVATE:
                state->flags.riseSequenceReady = 1;
                break;
            case DBSH_SHRINE_ANIM_EVENT_GRANT_SPIRIT:
                objSetAnimStateFlags(player, DBSH_SHRINE_PLAYER_ANIM_STATE_FLAG, 1);
                mainSetBits(DBSH_SHRINE_GAMEBIT_015F, 1);
                mainSetBits(GAMEBIT_ITEM_SpiritTestStrength_Got, 1);
                (*gMapEventInterface)->setMapAct(DBSH_SHRINE_REWARD_MAP_ID, DBSH_SHRINE_REWARD_MAP_ACT);
                unlockLevel(DBSH_SHRINE_UNLOCK_LEVEL, 0, 1);
                lockLevel(mapGetDirIdx(DBSH_SHRINE_LOCK_MAP_DIR_INDEX), 0);
                break;
            case DBSH_SHRINE_ANIM_EVENT_LOCK_POSE:
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                if (state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, 0, 1.0f);
                }
                break;
            case DBSH_SHRINE_ANIM_EVENT_UNLOCK_POSE:
                obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                if (state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, 0, 1.0f);
                }
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }

    return 0;
}

int dbshShrine_getExtraSize(void) {
    return sizeof(DBSHShrineState);
}

int dbshShrine_getObjectTypeId(void) {
    return 0;
}

void dbshShrine_free(GameObject* obj) {
    DBSHShrineState* state = obj->extra;

    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    gameTimerStop();
    objFreeObjectType(obj, DBSH_SHRINE_OBJ_GROUP);
    Music_Trigger(MUSICTRIG_DIM_Snow, 0);
    Music_Trigger(MUSICTRIG_CC_Visit1, 0);
    Music_Trigger(MUSICTRIG_vfp_walkabout, 0);
    Music_Trigger(MUSICTRIG_test_of_fear, 0);
    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 0);
    mainSetBits(GAMEBIT_SHRINE_MUSIC_LOCK, 1);
}

void dbshShrine_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    DBSHShrineState* state = obj->extra;

    if (visible == 0) {
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 0, 1.0f);
        }
    } else {
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 1, 1.0f);
        }
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        objDoParticleFx(obj, 1.0f, 7, 1.0f, state->light);
    }
}

void dbshShrine_hitDetect(void) {
}

void dbshShrine_update(GameObject* obj) {
    GameObject* player;
    u8 groupActive;
    DBSHShrineState* state = obj->extra;
    f32 idleSfxTimer;

    player = Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }

    if (obj->userData1 != 0) {
        obj->userData1--;
        if (obj->userData1 == 0) {
            skySetSlotFlag80(7, 1);
            getEnvfxAct(obj, player, DBSH_SHRINE_ENVFX_A, 0);
            getEnvfxAct(obj, player, DBSH_SHRINE_ENVFX_B, 0);
            getEnvfxAct(obj, player, DBSH_SHRINE_ENVFX_C, 0);
        }
    }

    dbshShrine_updateHoverMotion(obj);
    GameBitLatch_Update(&state->gameBitLatch, 2, -1, -1, DBSH_SHRINE_GAMEBIT_APPROACH, 0xE);
    GameBitLatch_UpdateInverted(&state->gameBitLatch, 1, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK, 8);
    GameBitLatch_Update(&state->gameBitLatch, 4, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK,
                        MUSICTRIG_PU3_Adventure_c4);

    switch ((DBSHShrinePhase)state->phase) {
    case DBSH_SHRINE_PHASE_WAITING:
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        idleSfxTimer = state->idleSfxTimer - timeDelta;
        state->idleSfxTimer = idleSfxTimer;
        if (idleSfxTimer <= 0.0f) {
            Sfx_PlayFromObject(obj, SFXTRIG_spirit_voice);
            state->idleSfxTimer = randomGetRange(500, 1000);
        }
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            groupActive = (*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, 1);
            if (groupActive != 0) {
                (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 1, 0);
            }
            state->phase = DBSH_SHRINE_PHASE_RISING;
            mainSetBits(DBSH_SHRINE_GAMEBIT_APPROACH, 1);
            obj->anim.rotX = DBSH_SHRINE_TRANSITION_ROTATION;
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            Music_Trigger(MUSICTRIG_DIM_Snow, 1);
        }
        break;
    case DBSH_SHRINE_PHASE_RISING:
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        if (state->flags.riseSequenceReady != 0) {
            state->phase = DBSH_SHRINE_PHASE_ACTIVE;
            mainSetBits(DBSH_GAMEBIT_SYMBOL_RISE_COMPLETE, 1);
        }
        break;
    case DBSH_SHRINE_PHASE_ACTIVE:
        if (mainGetBit(DBSH_GAMEBIT_SYMBOL_SPIN_SUCCEEDED) != 0) {
            state->phase = DBSH_SHRINE_PHASE_CLOSING;
            state->unknown0C = 0;
        } else if (mainGetBit(DBSH_GAMEBIT_SYMBOL_SPIN_FAILED) != 0) {
            state->phase = DBSH_SHRINE_PHASE_RESET;
            mainSetBits(DBSH_SHRINE_GAMEBIT_0C72, 1);
            state->unknown0C = 10;
        }
        break;
    case DBSH_SHRINE_PHASE_CLOSING:
        state->phase = DBSH_SHRINE_PHASE_RESET;
        audioStopByMask(3);
        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        mainSetBits(DBSH_SHRINE_GAMEBIT_APPROACH, 0);
        break;
    case DBSH_SHRINE_PHASE_RESET:
        state->phase = DBSH_SHRINE_PHASE_WAITING;
        state->flags.riseSequenceReady = 0;
        state->unknown0C = 0;
        mainSetBits(DBSH_SHRINE_GAMEBIT_APPROACH, 0);
        mainSetBits(DBSH_SHRINE_GAMEBIT_015F, 0);
        mainSetBits(DBSH_GAMEBIT_SYMBOL_RISE_COMPLETE, 0);
        mainSetBits(DBSH_GAMEBIT_SYMBOL_SPIN_SUCCEEDED, 0);
        mainSetBits(DBSH_GAMEBIT_SYMBOL_SPIN_FAILED, 0);
        mainSetBits(DBSH_SHRINE_GAMEBIT_0C72, 0);
        mainSetBits(DBSH_SHRINE_GAMEBIT_0C73, 0);
        break;
    }
}

void dbshShrine_init(GameObject* obj, const DBSHShrinePlacement* placement) {
    DBSHShrineState* state = obj->extra;

    (void)placement;
    obj->animEventCallback = dbshShrine_processAnimEvents;
    obj->anim.rotX = 0;
    state->phase = DBSH_SHRINE_PHASE_WAITING;
    state->flags.riseSequenceReady = 0;
    state->unknown0C = 0;

    ObjMsg_AllocQueue(obj, DBSH_SHRINE_MESSAGE_QUEUE_CAPACITY);
    mainSetBits(DBSH_SHRINE_GAMEBIT_015F, 0);

    if ((*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, 1) == 0) {
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 1, 1);
    }

    obj->anim.worldPosX = obj->anim.localPosX;
    obj->anim.worldPosY = obj->anim.localPosY;
    obj->anim.worldPosZ = obj->anim.localPosZ;
    obj->userData1 = 1;

    if (state->light == NULL) {
        state->light = objCreateLight(NULL, 1);
    }

    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 1);
    mainSetBits(DBSH_SHRINE_GAMEBIT_0F08, 1);
}

void dbshShrine_release(void) {
}

void dbshShrine_initialise(void) {
}

ObjectDescriptor gDBSHShrineObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dbshShrine_initialise,
    (ObjectDescriptorCallback)dbshShrine_release,
    0,
    (ObjectDescriptorCallback)dbshShrine_init,
    (ObjectDescriptorCallback)dbshShrine_update,
    (ObjectDescriptorCallback)dbshShrine_hitDetect,
    (ObjectDescriptorCallback)dbshShrine_render,
    (ObjectDescriptorCallback)dbshShrine_free,
    (ObjectDescriptorCallback)dbshShrine_getObjectTypeId,
    dbshShrine_getExtraSize,
};
