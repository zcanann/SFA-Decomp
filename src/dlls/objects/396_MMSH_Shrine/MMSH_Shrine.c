/*
 * MMSH_Shrine (DLL 0x18C) - Moon Mountain Pass Test of Fear shrine.
 *
 * The shrine bobs and turns toward the player, interprets animation commands, and
 * drives the fear-test sway meter and its object-trigger sequences.
 */
#include "dlls/objects/396_MMSH_Shrine.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/map_load.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/pad.h"
#include "main/pi_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/sky_api.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/model_light.h"

#define MMSH_SHRINE_CAMERA_MODE_ID 0x4C

#define MMSH_SHRINE_ENVFX_A 0x20D
#define MMSH_SHRINE_ENVFX_B 0x20E
#define MMSH_SHRINE_ENVFX_C 0x222

#define MMSH_SHRINE_MAP_DIRECTORY 0x20

#define MMSH_SHRINE_STATE_FLAG_SEQUENCE_READY    0x01
#define MMSH_SHRINE_STATE_FLAG_SWAY_ACTIVE       0x02
#define MMSH_SHRINE_STATE_FLAG_MUSIC_LATCH_04    0x04
#define MMSH_SHRINE_STATE_FLAG_MUSIC_LATCH_08    0x08
#define MMSH_SHRINE_STATE_FLAG_MUSIC_LATCH_10    0x10
#define MMSH_SHRINE_STATE_FLAG_FEAR_METER_ACTIVE 0x20

#define MMSH_SHRINE_ANIM_RESULT_COMPLETE 4
#define MMSH_SHRINE_MAP_ID               0xB
#define MMSH_SHRINE_MAP_ACT              3

#define MMSH_SHRINE_GAMEBIT_012A 0x12A
#define MMSH_SHRINE_GAMEBIT_012B 0x12B
#define MMSH_SHRINE_GAMEBIT_012D 0x12D
#define MMSH_SHRINE_GAMEBIT_0AE4 0xAE4
#define MMSH_SHRINE_GAMEBIT_0AE5 0xAE5
#define MMSH_SHRINE_GAMEBIT_0AE6 0xAE6
#define MMSH_SHRINE_GAMEBIT_0E82 0xE82
#define MMSH_SHRINE_GAMEBIT_0E83 0xE83
#define MMSH_SHRINE_GAMEBIT_0E84 0xE84
#define MMSH_SHRINE_GAMEBIT_0E85 0xE85

#define MMSH_SHRINE_MUSIC_TRIGGER_0A 0xA

#define MMSH_SHRINE_SEQUENCE_ACTIVATE        0
#define MMSH_SHRINE_SEQUENCE_PLAYER_INACTIVE 1
#define MMSH_SHRINE_SEQUENCE_READY           2
#define MMSH_SHRINE_SEQUENCE_SWAY_LIMIT      3

#define MMSH_SHRINE_PLAYER_ANIM_STATE_FLAG 4
#define MMSH_SHRINE_AUDIO_STOP_MASK        3

#define MMSH_SHRINE_SEQUENCE_FLAGS -1
#define MMSH_SHRINE_NO_GAMEBIT     -1

#define MMSH_SHRINE_SKY_FLAGS            7
#define MMSH_SHRINE_PARTICLE_TYPE        7
#define MMSH_SHRINE_LIGHT_DISABLED       0
#define MMSH_SHRINE_LIGHT_ENABLED        1
#define MMSH_SHRINE_LIGHT_FADE_DURATION  1.0f
#define MMSH_SHRINE_RENDER_SCALE         1.0f
#define MMSH_SHRINE_PARTICLE_SCALE       1.0f
#define MMSH_SHRINE_PARTICLE_EXTRA_SCALE 1.0f
#define MMSH_SHRINE_ENVFX_FLAGS          0
#define MMSH_SHRINE_LOAD_TIMER_START     1

#define MMSH_SHRINE_ORBIT_RATE_A         512.0f
#define MMSH_SHRINE_ORBIT_RATE_B         128.0f
#define MMSH_SHRINE_ORBIT_RATE_C         192.0f
#define MMSH_SHRINE_ORBIT_HEIGHT         20.0f
#define MMSH_SHRINE_ORBIT_ROTATION_SCALE 600.0f
#define MMSH_SHRINE_ANIMATION_STEP       0.005f
#define MMSH_SHRINE_TURN_RATE_DIVISOR    12.0f
#define MMSH_SHRINE_FADE_DISTANCE        30.0f
#define MMSH_SHRINE_FULL_ALPHA           255.0f
#define MMSH_SHRINE_ANGLE_HALF_TURN      0x8000
#define MMSH_SHRINE_ANGLE_WRAP           0xFFFF
#define MMSH_SHRINE_ORBIT_PI             3.1415927f
#define MMSH_SHRINE_ORBIT_ANGLE_SCALE    32768.0f

#define MMSH_SHRINE_FEAR_STICK_RANGE       72.0f
#define MMSH_SHRINE_FEAR_ACCELERATION_STEP 0.0010416667209938169f
#define MMSH_SHRINE_FEAR_METER_START       0x60
#define MMSH_SHRINE_FEAR_METER_END         0x39
#define MMSH_SHRINE_FEAR_METER_SCALE       96.0f

#define MMSH_SHRINE_SWAY_TARGET_STEP 0.0026041667442768812f

#define MMSH_SHRINE_IDLE_SFX_DELAY_MIN 500
#define MMSH_SHRINE_IDLE_SFX_DELAY_MAX 1000

#define MMSH_SHRINE_DEFAULT_INITIAL_VALUE 10
#define MMSH_SHRINE_INITIAL_VALUE_SHIFT   8

#define MMSH_SHRINE_LOAD_TIMER(obj) ((obj)->userData1)

typedef enum MMSHShrinePhase {
    MMSH_SHRINE_PHASE_IDLE = 0,
    MMSH_SHRINE_PHASE_WAIT_FOR_SEQUENCE = 1,
    MMSH_SHRINE_PHASE_WAIT_FOR_PLAYER = 2,
    MMSH_SHRINE_PHASE_SWAY_LIMIT = 3,
    MMSH_SHRINE_PHASE_SET_COMPLETE = 4,
    MMSH_SHRINE_PHASE_RESET = 5
} MMSHShrinePhase;

typedef enum MMSHShrineAnimCommand {
    MMSH_SHRINE_ANIM_COMMAND_ENABLE_SWAY = 1,
    MMSH_SHRINE_ANIM_COMMAND_DISABLE_SWAY = 2,
    MMSH_SHRINE_ANIM_COMMAND_TARGET_LEFT = 3,
    MMSH_SHRINE_ANIM_COMMAND_TARGET_RIGHT = 4,
    MMSH_SHRINE_ANIM_COMMAND_REVERSE_TARGET = 5,
    MMSH_SHRINE_ANIM_COMMAND_DOUBLE_TARGET = 6,
    MMSH_SHRINE_ANIM_COMMAND_GRANT_SPIRIT = 7,
    MMSH_SHRINE_ANIM_COMMAND_HALVE_TARGET = 8,
    MMSH_SHRINE_ANIM_COMMAND_HIDE_MODEL = 0xE,
    MMSH_SHRINE_ANIM_COMMAND_SHOW_MODEL = 0xF
} MMSHShrineAnimCommand;

ObjectDescriptor gMMSHShrineObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmshShrine_initialise,
    (ObjectDescriptorCallback)mmshShrine_release,
    0,
    (ObjectDescriptorCallback)mmshShrine_init,
    (ObjectDescriptorCallback)mmshShrine_update,
    (ObjectDescriptorCallback)mmshShrine_hitDetect,
    (ObjectDescriptorCallback)mmshShrine_render,
    (ObjectDescriptorCallback)mmshShrine_free,
    (ObjectDescriptorCallback)mmshShrine_getObjectTypeId,
    mmshShrine_getExtraSize,
};

void mmshShrine_updateHoverMotion(GameObject* obj) {
    const MMSHShrinePlacement* placement;
    MMSHShrineState* state;
    GameObject* player;
    f32 trigA;
    f32 trigB;
    s32 angleDelta;
    f32 distance;
    ObjAnimEventList animEvents;

    placement = (const MMSHShrinePlacement*)obj->anim.placementData;
    state = obj->extra;
    player = Obj_GetPlayerObject();

    if ((obj->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
        obj->anim.rotX = 0;
        obj->anim.localPosY = placement->base.posY;
        return;
    }

    state->orbitPhaseA = state->orbitPhaseA + (int)(MMSH_SHRINE_ORBIT_RATE_A * timeDelta);
    state->orbitPhaseB = state->orbitPhaseB + (int)(MMSH_SHRINE_ORBIT_RATE_B * timeDelta);
    state->orbitPhaseC = state->orbitPhaseC + (int)(MMSH_SHRINE_ORBIT_RATE_C * timeDelta);

    obj->anim.localPosY =
        MMSH_SHRINE_ORBIT_HEIGHT +
        (placement->base.posY + mathSinf((MMSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / MMSH_SHRINE_ORBIT_ANGLE_SCALE));

    trigA = mathSinf((MMSH_SHRINE_ORBIT_PI * state->orbitPhaseB) / MMSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = mathSinf((MMSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / MMSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB += trigA;
    obj->anim.rotZ = (s16)(MMSH_SHRINE_ORBIT_ROTATION_SCALE * trigB);

    trigA = mathSinf((MMSH_SHRINE_ORBIT_PI * state->orbitPhaseC) / MMSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = mathSinf((MMSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / MMSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB += trigA;
    obj->anim.rotY = (s16)(MMSH_SHRINE_ORBIT_ROTATION_SCALE * trigB);

    ObjAnim_AdvanceCurrentMove(obj, MMSH_SHRINE_ANIMATION_STEP, timeDelta, &animEvents);
    if (player == NULL) {
        return;
    }

    {
        f32 dx = obj->anim.worldPosX - player->anim.worldPosX;
        f32 dz = obj->anim.worldPosZ - player->anim.worldPosZ;
        int targetAngle = (u16)getAngle(dx, dz);

        angleDelta = targetAngle - (int)(u16)obj->anim.rotX;
        if (angleDelta > MMSH_SHRINE_ANGLE_HALF_TURN) {
            angleDelta -= MMSH_SHRINE_ANGLE_WRAP;
        }
        if (angleDelta < -MMSH_SHRINE_ANGLE_HALF_TURN) {
            angleDelta += MMSH_SHRINE_ANGLE_WRAP;
        }
        obj->anim.rotX =
            (s16)((int)*(s16*)&obj->anim.rotX + (int)(((f32)angleDelta * timeDelta) / MMSH_SHRINE_TURN_RATE_DIVISOR));
    }
    distance = Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX);
    if (distance <= MMSH_SHRINE_FADE_DISTANCE) {
        obj->anim.alpha = (u8)(int)(MMSH_SHRINE_FULL_ALPHA * (distance / MMSH_SHRINE_FADE_DISTANCE));
    } else {
        obj->anim.alpha = 0xFF;
    }
}

int mmshShrine_updateFearSway(GameObject* obj) {
    MMSHShrineState* state;
    f32 stickAccel;
    f32 target;
    f32 zero;
    int swayValue;

    state = obj->extra;
    if ((state->latch.activeMask & MMSH_SHRINE_STATE_FLAG_FEAR_METER_ACTIVE) == 0) {
        fearTestMeterSetFadeIn(1);
        state->latch.activeMask |= MMSH_SHRINE_STATE_FLAG_FEAR_METER_ACTIVE;
        zero = 0.0f;
        state->swayPhase = zero;
        state->stickVelocity = zero;
        state->targetVelocity = zero;
    }

    stickAccel = (f32)padGetStickX(0) / MMSH_SHRINE_FEAR_STICK_RANGE;
    stickAccel *= MMSH_SHRINE_FEAR_ACCELERATION_STEP;
    state->stickVelocity += stickAccel * timeDelta;

    target = state->swayTarget;
    if (target < 0.0f && state->targetVelocity > target) {
        state->targetVelocity -= MMSH_SHRINE_FEAR_ACCELERATION_STEP * timeDelta;
    } else if (target > 0.0f) {
        if (state->targetVelocity < target) {
            state->targetVelocity += MMSH_SHRINE_FEAR_ACCELERATION_STEP * timeDelta;
        }
    }

    state->swayPhase += timeDelta * (state->stickVelocity + state->targetVelocity);
    swayValue = (int)(MMSH_SHRINE_FEAR_METER_SCALE * state->swayPhase);
    fearTestMeterSetRange(MMSH_SHRINE_FEAR_METER_START, MMSH_SHRINE_FEAR_METER_END, (s16)swayValue);
    if ((swayValue > MMSH_SHRINE_FEAR_METER_END) || (swayValue < -MMSH_SHRINE_FEAR_METER_END)) {
        return 1;
    }
    return 0;
}

int mmshShrine_processAnimEvents(GameObject* obj, int unusedArg, ObjSeqState* animUpdate) {
    MMSHShrineState* state;
    u8 command;
    GameObject* player;
    int i;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    animUpdate->savedFlags = -1;
    animUpdate->movementState = 0;

    for (i = 0; i < (int)(u32)animUpdate->eventCount; i++) {
        command = animUpdate->eventIds[i];
        if (command != 0) {
            switch (command) {
            case MMSH_SHRINE_ANIM_COMMAND_GRANT_SPIRIT:
                objSetAnimStateFlags(player, MMSH_SHRINE_PLAYER_ANIM_STATE_FLAG, 1);
                mainSetBits(MMSH_SHRINE_GAMEBIT_012A, 1);
                mainSetBits(GAMEBIT_ITEM_SpiritTestFear_Got, 1);
                (*gMapEventInterface)->setMapAct(MMSH_SHRINE_MAP_ID, MMSH_SHRINE_MAP_ACT);
                break;
            case MMSH_SHRINE_ANIM_COMMAND_HIDE_MODEL:
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                if (state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, MMSH_SHRINE_LIGHT_DISABLED,
                                                MMSH_SHRINE_LIGHT_FADE_DURATION);
                }
                break;
            case MMSH_SHRINE_ANIM_COMMAND_SHOW_MODEL:
                obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                if (state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, MMSH_SHRINE_LIGHT_DISABLED,
                                                MMSH_SHRINE_LIGHT_FADE_DURATION);
                }
                break;
            case MMSH_SHRINE_ANIM_COMMAND_ENABLE_SWAY:
                state->latch.activeMask |= MMSH_SHRINE_STATE_FLAG_SWAY_ACTIVE;
                break;
            case MMSH_SHRINE_ANIM_COMMAND_DISABLE_SWAY:
                state->latch.activeMask &= ~MMSH_SHRINE_STATE_FLAG_SWAY_ACTIVE;
                if ((state->latch.activeMask & MMSH_SHRINE_STATE_FLAG_FEAR_METER_ACTIVE) != 0) {
                    fearTestMeterSetFadeIn(0);
                    state->latch.activeMask &= ~MMSH_SHRINE_STATE_FLAG_FEAR_METER_ACTIVE;
                }
                break;
            case MMSH_SHRINE_ANIM_COMMAND_TARGET_LEFT:
                state->swayTarget = -MMSH_SHRINE_SWAY_TARGET_STEP;
                break;
            case MMSH_SHRINE_ANIM_COMMAND_TARGET_RIGHT:
                state->swayTarget = MMSH_SHRINE_SWAY_TARGET_STEP;
                break;
            case MMSH_SHRINE_ANIM_COMMAND_REVERSE_TARGET:
                state->swayTarget = -state->swayTarget;
                state->targetVelocity = -state->swayTarget;
                break;
            case MMSH_SHRINE_ANIM_COMMAND_DOUBLE_TARGET:
                state->swayTarget *= 2.0f;
                break;
            case MMSH_SHRINE_ANIM_COMMAND_HALVE_TARGET:
                state->swayTarget *= 0.5f;
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }

    if (((state->latch.activeMask & MMSH_SHRINE_STATE_FLAG_SWAY_ACTIVE) != 0) &&
        ((u8)mmshShrine_updateFearSway(obj) != 0)) {
        fearTestMeterSetFadeIn(0);
        state->latch.activeMask &= ~(MMSH_SHRINE_STATE_FLAG_SWAY_ACTIVE | MMSH_SHRINE_STATE_FLAG_FEAR_METER_ACTIVE);
        state->phase = MMSH_SHRINE_PHASE_SWAY_LIMIT;
        mainSetBits(MMSH_SHRINE_GAMEBIT_0E82, 0);
        mainSetBits(MMSH_SHRINE_GAMEBIT_0E83, 0);
        mainSetBits(MMSH_SHRINE_GAMEBIT_0E84, 0);
        mainSetBits(MMSH_SHRINE_GAMEBIT_0E85, 0);
        return MMSH_SHRINE_ANIM_RESULT_COMPLETE;
    }
    state->latch.activeMask |= MMSH_SHRINE_STATE_FLAG_SEQUENCE_READY;
    return 0;
}

int mmshShrine_getExtraSize(void) {
    return sizeof(MMSHShrineState);
}

int mmshShrine_getObjectTypeId(void) {
    return 0;
}

void mmshShrine_free(GameObject* obj) {
    MMSHShrineState* state = obj->extra;

    if ((state->latch.activeMask & MMSH_SHRINE_STATE_FLAG_FEAR_METER_ACTIVE) != 0) {
        fearTestMeterSetFadeIn(0);
        state->latch.activeMask &= ~MMSH_SHRINE_STATE_FLAG_FEAR_METER_ACTIVE;
    }
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    Music_Trigger(MUSICTRIG_DIM_Snow, 0);
    Music_Trigger(MUSICTRIG_CC_Visit1, 0);
    Music_Trigger(MUSICTRIG_vfp_walkabout, 0);
    Music_Trigger(MMSH_SHRINE_MUSIC_TRIGGER_0A, 0);
    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 0);
    mainSetBits(GAMEBIT_SHRINE_MUSIC_LOCK, 1);
    mainSetBits(MMSH_SHRINE_GAMEBIT_0E82, 0);
    mainSetBits(MMSH_SHRINE_GAMEBIT_0E83, 0);
    mainSetBits(MMSH_SHRINE_GAMEBIT_0E84, 0);
    mainSetBits(MMSH_SHRINE_GAMEBIT_0E85, 0);
}

void mmshShrine_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    MMSHShrineState* state = obj->extra;

    if (visible == 0) {
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, MMSH_SHRINE_LIGHT_DISABLED, MMSH_SHRINE_LIGHT_FADE_DURATION);
        }
    } else {
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, MMSH_SHRINE_LIGHT_ENABLED, MMSH_SHRINE_LIGHT_FADE_DURATION);
        }
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, MMSH_SHRINE_RENDER_SCALE);
        objDoParticleFx(obj, MMSH_SHRINE_PARTICLE_SCALE, MMSH_SHRINE_PARTICLE_TYPE,
                               MMSH_SHRINE_PARTICLE_EXTRA_SCALE, state->light);
    }
}

void mmshShrine_hitDetect(void) {
}

void mmshShrine_update(GameObject* obj) {
    MMSHShrineState* state;
    GameObject* player;

    state = obj->extra;
    player = Obj_GetPlayerObject();

    if (MMSH_SHRINE_LOAD_TIMER(obj) != 0) {
        MMSH_SHRINE_LOAD_TIMER(obj)--;
        if (MMSH_SHRINE_LOAD_TIMER(obj) == 0) {
            skySetSlotFlag80(MMSH_SHRINE_SKY_FLAGS, 1);
            getEnvfxAct(obj, player, MMSH_SHRINE_ENVFX_A, MMSH_SHRINE_ENVFX_FLAGS);
            getEnvfxAct(obj, player, MMSH_SHRINE_ENVFX_B, MMSH_SHRINE_ENVFX_FLAGS);
            getEnvfxAct(obj, player, MMSH_SHRINE_ENVFX_C, MMSH_SHRINE_ENVFX_FLAGS);
            obj->anim.worldPosX = obj->anim.localPosX;
            obj->anim.worldPosY = obj->anim.localPosY;
            obj->anim.worldPosZ = obj->anim.localPosZ;
        }
    }
    unlockLevel(mapGetDirIdx(MMSH_SHRINE_MAP_DIRECTORY), 1, 0);
    mmshShrine_updateHoverMotion(obj);
    GameBitLatch_Update(&state->latch, MMSH_SHRINE_STATE_FLAG_MUSIC_LATCH_08, MMSH_SHRINE_NO_GAMEBIT,
                          MMSH_SHRINE_NO_GAMEBIT, MMSH_SHRINE_GAMEBIT_0AE6, MMSH_SHRINE_MUSIC_TRIGGER_0A);
    GameBitLatch_UpdateInverted(&state->latch, MMSH_SHRINE_STATE_FLAG_MUSIC_LATCH_04, MMSH_SHRINE_NO_GAMEBIT,
                                  MMSH_SHRINE_NO_GAMEBIT, GAMEBIT_SHRINE_MUSIC_LOCK, MUSICTRIG_vfp_walkabout);
    GameBitLatch_Update(&state->latch, MMSH_SHRINE_STATE_FLAG_MUSIC_LATCH_10, MMSH_SHRINE_NO_GAMEBIT,
                          MMSH_SHRINE_NO_GAMEBIT, GAMEBIT_SHRINE_MUSIC_LOCK, MUSICTRIG_PU3_Adventure_c4);

    switch (state->phase) {
    case MMSH_SHRINE_PHASE_IDLE: {
        f32 idleSfxTimer = state->idleSfxTimer - timeDelta;

        state->idleSfxTimer = idleSfxTimer;
        if (idleSfxTimer <= 0.0f) {
            Sfx_PlayFromObject(obj, SFXTRIG_spirit_voice);
            state->idleSfxTimer =
                (f32)(s32)randomGetRange(MMSH_SHRINE_IDLE_SFX_DELAY_MIN, MMSH_SHRINE_IDLE_SFX_DELAY_MAX);
        }
    }
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) == 0) {
            break;
        }
        state->phase = MMSH_SHRINE_PHASE_WAIT_FOR_SEQUENCE;
        (*gObjectTriggerInterface)->setCamVars(MMSH_SHRINE_CAMERA_MODE_ID, 0, 0, 0);
        (*gObjectTriggerInterface)->runSequence(MMSH_SHRINE_SEQUENCE_ACTIVATE, obj, MMSH_SHRINE_SEQUENCE_FLAGS);
        Music_Trigger(MUSICTRIG_DIM_Snow, 1);
        break;
    case MMSH_SHRINE_PHASE_WAIT_FOR_SEQUENCE:
        if ((state->latch.activeMask & MMSH_SHRINE_STATE_FLAG_SEQUENCE_READY) == 0) {
            break;
        }
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        obj->anim.rotX = 0;
        state->phase = MMSH_SHRINE_PHASE_WAIT_FOR_PLAYER;
        state->latch.activeMask &= ~MMSH_SHRINE_STATE_FLAG_SEQUENCE_READY;
        mainSetBits(MMSH_SHRINE_GAMEBIT_0AE6, 1);
        (*gObjectTriggerInterface)->runSequence(MMSH_SHRINE_SEQUENCE_READY, obj, MMSH_SHRINE_SEQUENCE_FLAGS);
        break;
    case MMSH_SHRINE_PHASE_SWAY_LIMIT:
        (*gObjectTriggerInterface)->endSequence(obj->seqIndex);
        (*gObjectTriggerInterface)->runSequence(MMSH_SHRINE_SEQUENCE_SWAY_LIMIT, obj, MMSH_SHRINE_SEQUENCE_FLAGS);
        state->phase = MMSH_SHRINE_PHASE_SET_COMPLETE;
        mainSetBits(MMSH_SHRINE_GAMEBIT_0AE6, 0);
        break;
    case MMSH_SHRINE_PHASE_SET_COMPLETE:
        state->phase = MMSH_SHRINE_PHASE_RESET;
        mainSetBits(MMSH_SHRINE_GAMEBIT_0AE6, 0);
        mainSetBits(MMSH_SHRINE_GAMEBIT_0AE4, 1);
        break;
    case MMSH_SHRINE_PHASE_WAIT_FOR_PLAYER:
        if (objGetAnimStateFlags(player, MMSH_SHRINE_PLAYER_ANIM_STATE_FLAG) == 0) {
            audioStopByMask(MMSH_SHRINE_AUDIO_STOP_MASK);
            (*gObjectTriggerInterface)
                ->runSequence(MMSH_SHRINE_SEQUENCE_PLAYER_INACTIVE, obj, MMSH_SHRINE_SEQUENCE_FLAGS);
        }
        state->phase = MMSH_SHRINE_PHASE_RESET;
        mainSetBits(MMSH_SHRINE_GAMEBIT_0AE6, 0);
        break;
    case MMSH_SHRINE_PHASE_RESET:
        state->phase = MMSH_SHRINE_PHASE_IDLE;
        state->latch.activeMask &= ~MMSH_SHRINE_STATE_FLAG_SEQUENCE_READY;
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        mainSetBits(MMSH_SHRINE_GAMEBIT_012B, 0);
        mainSetBits(MMSH_SHRINE_GAMEBIT_0AE4, 0);
        mainSetBits(MMSH_SHRINE_GAMEBIT_0AE5, 0);
        mainSetBits(MMSH_SHRINE_GAMEBIT_0AE6, 0);
        break;
    }
}

void mmshShrine_init(GameObject* obj, const MMSHShrinePlacement* placement) {
    ModelLightStruct* light;
    MMSHShrineState* state;

    state = obj->extra;
    obj->anim.rotX = 0;
    obj->animEventCallback = mmshShrine_processAnimEvents;
    state->unknown1C = MMSH_SHRINE_DEFAULT_INITIAL_VALUE;
    state->phase = MMSH_SHRINE_PHASE_IDLE;
    if (placement->initialValue > 0) {
        state->unknown1C = placement->initialValue >> MMSH_SHRINE_INITIAL_VALUE_SHIFT;
    }
    mainSetBits(MMSH_SHRINE_GAMEBIT_012B, 0);
    mainSetBits(MMSH_SHRINE_GAMEBIT_012D, 0);
    MMSH_SHRINE_LOAD_TIMER(obj) = MMSH_SHRINE_LOAD_TIMER_START;
    if (state->light == NULL) {
        light = objCreateLight(NULL, 1);
        state->light = light;
    }
    mainSetBits(GAMEBIT_LV_LocatedKrazoaShrine, 1);
    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 1);
}

void mmshShrine_release(void) {
}

void mmshShrine_initialise(void) {
}
