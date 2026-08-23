/*
 * ECSH_Shrine (DLL 0x18F) - Krazoa Shrine Test of Observation.
 *
 * Runs the three-round cup shuffle, the floating shrine model, and the
 * animation events that drive the test's camera, lighting, and reward.
 */
#include "dlls/objects/399_ECSH_Shrine.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "game/objects/object_setup.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/dll/player_staff_api.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/objseq.h"
#include "main/render_envfx_api.h"
#include "main/screen_transition.h"
#include "main/sky_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

typedef struct ECSHShrineWordPair {
    u32 first;
    u32 second;
} ECSHShrineWordPair;

typedef struct ECSHShrineCupPosition {
    f32 x;
    f32 z;
} ECSHShrineCupPosition;

typedef struct ECSHShrinePuzzleScratch {
    f32 cupPositions[12];
    s16 cupSlotMap[6];
    s16 nextCupSlotMap[6];
} ECSHShrinePuzzleScratch;

STATIC_ASSERT(offsetof(ECSHShrinePuzzleScratch, cupPositions) == 0x00);
STATIC_ASSERT(offsetof(ECSHShrinePuzzleScratch, cupSlotMap) == 0x30);
STATIC_ASSERT(offsetof(ECSHShrinePuzzleScratch, nextCupSlotMap) == 0x3C);
STATIC_ASSERT(sizeof(ECSHShrinePuzzleScratch) == 0x48);
STATIC_ASSERT(sizeof(ECSHShrineCupPosition) == 0x08);

#define ECSH_SHRINE_CAMERA_MODE_STATIC 0x48

#define ECSH_SHRINE_ENVFX_A 0x221
#define ECSH_SHRINE_ENVFX_B 0x220
#define ECSH_SHRINE_ENVFX_C 0x222

#define ECSH_SHRINE_CUP_COUNT      6
#define ECSH_SHRINE_LAST_CUP_INDEX 5

#define ECSH_SHRINE_PLAYER_ANIM_STATE_FLAG 8
#define ECSH_SHRINE_AUDIO_STOP_MASK        3
#define ECSH_SHRINE_STAFF_DISABLED         0

#define ECSH_SHRINE_CAMERA_ARG1 100
#define ECSH_SHRINE_CAMERA_ARG2 0
#define ECSH_SHRINE_CAMERA_ARG3 0x50

#define ECSH_SHRINE_DIALOGUE_ID            0x285
#define ECSH_SHRINE_DIALOGUE_UNUSED_A      0x14
#define ECSH_SHRINE_DIALOGUE_UNUSED_B      0x8C
#define ECSH_SHRINE_DIALOGUE_DISABLE_INPUT 1

#define ECSH_SHRINE_SKY_FLAGS   7
#define ECSH_SHRINE_ENVFX_FLAGS 0

#define ECSH_SHRINE_LIGHT_DISABLED       0
#define ECSH_SHRINE_LIGHT_ENABLED        1
#define ECSH_SHRINE_LIGHT_FADE_DURATION  1.0f
#define ECSH_SHRINE_RENDER_SCALE         1.0f
#define ECSH_SHRINE_PARTICLE_SCALE       1.0f
#define ECSH_SHRINE_PARTICLE_TYPE        7
#define ECSH_SHRINE_PARTICLE_EXTRA_SCALE 1.0f

#define ECSH_SHRINE_SEQUENCE_INTRO   0
#define ECSH_SHRINE_SEQUENCE_SUCCESS 1
#define ECSH_SHRINE_SEQUENCE_ROUND   2
#define ECSH_SHRINE_SEQUENCE_FLAGS   -1

#define ECSH_SHRINE_STATE_FLAG_TEST_RUNNING   0x02
#define ECSH_SHRINE_STATE_FLAG_MUSIC_LATCH_01 0x01
#define ECSH_SHRINE_STATE_FLAG_MUSIC_LATCH_10 0x10
#define ECSH_SHRINE_NO_GAMEBIT                -1

#define ECSH_SHRINE_VOICE_DELAY_MIN 500
#define ECSH_SHRINE_VOICE_DELAY_MAX 1000

#define ECSH_SHRINE_INTRO_COOLDOWN           200.0f
#define ECSH_SHRINE_INTRO_TRANSITION_FRAMES  0x78
#define ECSH_SHRINE_ROUND_START_COOLDOWN     80.0f
#define ECSH_SHRINE_SHUFFLE_ANIM_TIMER       40.0f
#define ECSH_SHRINE_SHUFFLE_COOLDOWN         60.0f
#define ECSH_SHRINE_GUESS_TIMER              600.0f
#define ECSH_SHRINE_SHUFFLE_SFX_DELAY_MIN    0x28
#define ECSH_SHRINE_SHUFFLE_SFX_DELAY_MAX    0x3C
#define ECSH_SHRINE_SHUFFLE_START_TIMER      2.0f
#define ECSH_SHRINE_SHUFFLE_MOVE_TIMER       100.0f
#define ECSH_SHRINE_RESULT_TRANSITION_FRAMES 0x1E
#define ECSH_SHRINE_RESULT_COOLDOWN          31.0f
#define ECSH_SHRINE_NEXT_ROUND_COOLDOWN      150.0f
#define ECSH_SHRINE_NEXT_ROUND_ANIM_TIMER    12.0f
#define ECSH_SHRINE_RESET_COOLDOWN           400.0f

#define ECSH_SHRINE_ROUND_ONE_SHUFFLES   5
#define ECSH_SHRINE_ROUND_TWO_SHUFFLES   7
#define ECSH_SHRINE_ROUND_THREE_SHUFFLES 9

#define ECSH_SHRINE_ROUND_ONE_PATTERN_MAX   1
#define ECSH_SHRINE_ROUND_TWO_PATTERN_MAX   5
#define ECSH_SHRINE_ROUND_THREE_PATTERN_MAX 7

#define ECSH_SHRINE_SHUFFLE_SFX_ROLL_MAX       10
#define ECSH_SHRINE_SHUFFLE_SFX_ROLL_THRESHOLD 7

#define ECSH_SHRINE_MESSAGE_QUEUE_CAPACITY 4
#define ECSH_SHRINE_LOAD_TIMER_START       1

#define ECSH_SHRINE_PLACEMENT_ROTATION_OFFSET 0x18
#define ECSH_SHRINE_PLACEMENT_ROTATION_SHIFT  8

#define ECSH_SHRINE_GAMEBIT_0A6D 0xA6D
#define ECSH_SHRINE_GAMEBIT_0A6F 0xA6F
#define ECSH_SHRINE_GAMEBIT_0A70 0xA70

#define ECSH_SHRINE_UNKNOWN_18_INITIAL 0x0C
#define ECSH_SHRINE_UNKNOWN_1C_INITIAL 0x1E

#define ECSH_SHRINE_ORBIT_RATE_A         512.0f
#define ECSH_SHRINE_ORBIT_RATE_B         128.0f
#define ECSH_SHRINE_ORBIT_RATE_C         192.0f
#define ECSH_SHRINE_ORBIT_HEIGHT         20.0f
#define ECSH_SHRINE_ORBIT_ROTATION_SCALE 600.0f
#define ECSH_SHRINE_ANIMATION_STEP       0.005f
#define ECSH_SHRINE_TURN_RATE_DIVISOR    12.0f
#define ECSH_SHRINE_FADE_DISTANCE        30.0f
#define ECSH_SHRINE_FULL_ALPHA           255.0f
#define ECSH_SHRINE_ANGLE_HALF_TURN      0x8000
#define ECSH_SHRINE_ANGLE_WRAP           0xFFFF
#define ECSH_SHRINE_ORBIT_PI             3.1415927f
#define ECSH_SHRINE_ORBIT_ANGLE_SCALE    32768.0f

enum {
    ECSH_SHRINE_ANIM_EVENT_TRANSITION_READY = 3,
    ECSH_SHRINE_ANIM_EVENT_GRANT_SPIRIT = 7,
    ECSH_SHRINE_ANIM_EVENT_SET_CAMERA = 13,
    ECSH_SHRINE_ANIM_EVENT_LOCK_POSE = 14,
    ECSH_SHRINE_ANIM_EVENT_UNLOCK_POSE = 15,
};

typedef enum ECSHShrinePhase {
    ECSH_SHRINE_PHASE_IDLE = 0,
    ECSH_SHRINE_PHASE_INTRO_TRANSITION = 1,
    ECSH_SHRINE_PHASE_PREPARE_ROUND_ONE = 2,
    ECSH_SHRINE_PHASE_ROUND_ONE = 3,
    ECSH_SHRINE_PHASE_ROUND_TWO = 4,
    ECSH_SHRINE_PHASE_ROUND_THREE = 5,
    ECSH_SHRINE_PHASE_SUCCESS = 6,
    ECSH_SHRINE_PHASE_POST_SUCCESS = 7,
    ECSH_SHRINE_PHASE_RESET = 8,
    ECSH_SHRINE_PHASE_FAIL = 10,
} ECSHShrinePhase;

GameObject* gECSHShrineActiveObject;
int lbl_803DDBC0;
extern u32 lbl_803E8470;

ECSHShrineCupPosition gECSHShrineCupPositions[ECSH_SHRINE_CUP_COUNT] = {0};

s16 gECSHShrineCupSlotMap[ECSH_SHRINE_CUP_COUNT * 2] = {
    0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5,
};

ObjectDescriptor15 gECSHShrineObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_15_SLOTS,
    (ObjectDescriptorCallback)ecshShrine_initialise,
    (ObjectDescriptorCallback)ecshShrine_release,
    0,
    (ObjectDescriptorCallback)ecshShrine_init,
    (ObjectDescriptorCallback)ecshShrine_update,
    (ObjectDescriptorCallback)ecshShrine_hitDetect,
    (ObjectDescriptorCallback)ecshShrine_render,
    (ObjectDescriptorCallback)ecshShrine_free,
    (ObjectDescriptorCallback)ecshShrine_getObjectTypeId,
    ecshShrine_getExtraSize,
    (ObjectDescriptorCallback)ecshShrine_func0A,
    (ObjectDescriptorCallback)ecshShrine_getCupPosition,
    (ObjectDescriptorCallback)ecshShrine_getPhaseAndSpiritCup,
    (ObjectDescriptorCallback)ecshShrine_setCupPosition,
    (ObjectDescriptorCallback)ecshShrine_checkCupPick,
};

void ecshShrine_updateHoverMotion(GameObject* obj) {
    const ObjPlacement* placement;
    ECSHShrineState* state;
    GameObject* player;
    f32 trigA;
    f32 trigB;
    f32 distance;
    s32 angleDelta;
    ObjAnimEventList animEvents;

    placement = (const ObjPlacement*)obj->anim.placementData;
    state = obj->extra;
    player = Obj_GetPlayerObject();

    if ((obj->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
        obj->anim.rotX = 0;
        obj->anim.localPosY = placement->posY;
        return;
    }

    state->orbitPhaseA = state->orbitPhaseA + (s32)(ECSH_SHRINE_ORBIT_RATE_A * timeDelta);
    state->orbitPhaseB = state->orbitPhaseB + (s32)(ECSH_SHRINE_ORBIT_RATE_B * timeDelta);
    state->orbitPhaseC = state->orbitPhaseC + (s32)(ECSH_SHRINE_ORBIT_RATE_C * timeDelta);

    obj->anim.localPosY =
        ECSH_SHRINE_ORBIT_HEIGHT +
        (placement->posY + mathSinf((ECSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / ECSH_SHRINE_ORBIT_ANGLE_SCALE));

    trigA = mathSinf((ECSH_SHRINE_ORBIT_PI * state->orbitPhaseB) / ECSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = mathSinf((ECSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / ECSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = trigB + trigA;
    obj->anim.rotZ = ECSH_SHRINE_ORBIT_ROTATION_SCALE * trigB;

    trigA = mathSinf((ECSH_SHRINE_ORBIT_PI * state->orbitPhaseC) / ECSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = mathSinf((ECSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / ECSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = trigB + trigA;
    obj->anim.rotY = ECSH_SHRINE_ORBIT_ROTATION_SCALE * trigB;

    ObjAnim_AdvanceCurrentMove(obj, ECSH_SHRINE_ANIMATION_STEP, timeDelta, &animEvents);

    if (player != NULL) {
        angleDelta =
            (u16)getAngle(obj->anim.worldPosX - player->anim.worldPosX, obj->anim.worldPosZ - player->anim.worldPosZ) -
            (u16)obj->anim.rotX;
        if (angleDelta > ECSH_SHRINE_ANGLE_HALF_TURN) {
            angleDelta -= ECSH_SHRINE_ANGLE_WRAP;
        }
        if (angleDelta < -ECSH_SHRINE_ANGLE_HALF_TURN) {
            angleDelta += ECSH_SHRINE_ANGLE_WRAP;
        }

        obj->anim.rotX =
            (s16)(*(s16*)(int)&obj->anim.rotX + (s32)(((f32)angleDelta * timeDelta) / ECSH_SHRINE_TURN_RATE_DIVISOR));
        distance = Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX);
        if (distance <= ECSH_SHRINE_FADE_DISTANCE) {
            obj->anim.alpha = (u8)(s32)(ECSH_SHRINE_FULL_ALPHA * (distance / ECSH_SHRINE_FADE_DISTANCE));
        } else {
            obj->anim.alpha = 0xFF;
        }
    }
}

int ecshShrine_processAnimEvents(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    ECSHShrineState* state;
    GameObject* player;
    int i;
    u8 event;

    (void)unused;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    animUpdate->savedFlags = -1;
    animUpdate->movementState = 0;

    for (i = 0; i < animUpdate->eventCount; i++) {
        event = animUpdate->eventIds[i];
        if (event != 0) {
            switch (event) {
            case ECSH_SHRINE_ANIM_EVENT_TRANSITION_READY:
                state->transitionReady = 1;
                break;
            case ECSH_SHRINE_ANIM_EVENT_GRANT_SPIRIT:
                objSetAnimStateFlags(player, ECSH_SHRINE_PLAYER_ANIM_STATE_FLAG, 1);
                mainSetBits(GAMEBIT_WM_Spirit1Related_0143, 1);
                mainSetBits(GAMEBIT_K1_SPIRIT_COLLECTED, 1);
                break;
            case ECSH_SHRINE_ANIM_EVENT_SET_CAMERA:
                (*gObjectTriggerInterface)
                    ->setCamVars(ECSH_SHRINE_CAMERA_MODE_STATIC, ECSH_SHRINE_CAMERA_ARG1, ECSH_SHRINE_CAMERA_ARG2,
                                 ECSH_SHRINE_CAMERA_ARG3);
                break;
            case ECSH_SHRINE_ANIM_EVENT_LOCK_POSE:
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                if (state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, ECSH_SHRINE_LIGHT_DISABLED,
                                                ECSH_SHRINE_LIGHT_FADE_DURATION);
                }
                break;
            case ECSH_SHRINE_ANIM_EVENT_UNLOCK_POSE:
                obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                if (state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, ECSH_SHRINE_LIGHT_DISABLED,
                                                ECSH_SHRINE_LIGHT_FADE_DURATION);
                }
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }

    return 0;
}

void ecshShrine_checkCupPick(u8 cupIndex) {
    GameObject* obj = gECSHShrineActiveObject;
    ECSHShrineState* state;

    if (obj == NULL) {
        return;
    }
    state = obj->extra;
    if (cupIndex == state->spiritCup) {
        state->matchFlag = 1;
    } else {
        state->matchFlag = 0;
    }
}

void ecshShrine_setCupPosition(u8 cupIndex, f32 x, f32 z) {
    int slot;

    if (gECSHShrineActiveObject == NULL) {
        return;
    }
    slot = gECSHShrineCupSlotMap[cupIndex];
    gECSHShrineCupPositions[slot].x = x;
    gECSHShrineCupPositions[slot].z = z;
}

void ecshShrine_getPhaseAndSpiritCup(int* outAnimState, u8* outSpiritCup) {
    GameObject* obj = gECSHShrineActiveObject;
    ECSHShrineState* state;

    if (obj == NULL) {
        return;
    }
    state = obj->extra;
    *outSpiritCup = state->spiritCup;
    *outAnimState = state->animState;
}

void ecshShrine_getCupPosition(u8 cupIndex, f32* outX, f32* outZ) {
    int slot;

    if (gECSHShrineActiveObject == NULL) {
        return;
    }
    slot = gECSHShrineCupSlotMap[cupIndex];
    *outX = gECSHShrineCupPositions[slot].x;
    slot = gECSHShrineCupSlotMap[cupIndex];
    *outZ = gECSHShrineCupPositions[slot].z;
}

void ecshShrine_func0A(s16* out) {
    GameObject* obj = gECSHShrineActiveObject;
    ECSHShrineState* state;

    if (obj == NULL) {
        return;
    }
    state = obj->extra;
    *out = state->unknown20;
}

int ecshShrine_getExtraSize(void) {
    return sizeof(ECSHShrineState);
}

int ecshShrine_getObjectTypeId(void) {
    return 0;
}

void ecshShrine_free(GameObject* obj) {
    ECSHShrineState* state = obj->extra;

    Music_Trigger(MUSICTRIG_DIM_Snow, 0);
    Music_Trigger(MUSICTRIG_CC_Visit1, 0);
    Music_Trigger(MUSICTRIG_vfp_walkabout, 0);
    Music_Trigger(MUSICTRIG_krazoa_doors_open, 0);
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    objFreeObjectType(obj, ECSH_SHRINE_OBJECT_GROUP);
    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 0);
    mainSetBits(GAMEBIT_SHRINE_MUSIC_LOCK, 1);
    mainSetBits(GAMEBIT_WMRelated0A7F, 1);
}

void ecshShrine_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    ECSHShrineState* state = obj->extra;

    if (visible == 0) {
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, ECSH_SHRINE_LIGHT_DISABLED, ECSH_SHRINE_LIGHT_FADE_DURATION);
        }
        return;
    }
    if (state->light != NULL) {
        modelLightStruct_setEnabled(state->light, ECSH_SHRINE_LIGHT_ENABLED, ECSH_SHRINE_LIGHT_FADE_DURATION);
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, ECSH_SHRINE_RENDER_SCALE);
    objDoParticleFx(obj, ECSH_SHRINE_PARTICLE_SCALE, ECSH_SHRINE_PARTICLE_TYPE, ECSH_SHRINE_PARTICLE_EXTRA_SCALE,
                    state->light);
}

void ecshShrine_hitDetect(void) {
}

/*
 * Main state machine.
 *
 * Outer phase = ECSHShrineState.testPhase:
 *   0  idle / waiting for player to engage
 *   1  intro screen transition
 *   2  spirit hides and selects the target cup (spiritCup = randomGetRange(0,5))
 *   3  round 1 (5 shuffles, pattern randomGetRange(0,1))
 *   4  round 2 (7 shuffles, pattern randomGetRange(0,5))
 *   5  round 3 (9 shuffles, pattern randomGetRange(0,7))
 *   6  win cutscene (all 3 rounds passed)
 *   7  reset step
 *   8  reset step (clears state back to idle)
 *   10 fail / teleport player out
 *
 * Inner shuffle-animation state = ECSHShrineState.animState (0x24), values 0-9:
 *   drives the per-step cup shuffle animation and SFX; transitions cycle
 *   8->2->5/0->1->4->2 etc. as each shuffle iteration plays out, with 7/9
 *   used as round-entry/exit and 5 as the guess-resolution state.
 */
void ecshShrine_update(GameObject* obj) {
    f32 cupPositionSwap[2];
    int messageArgC;
    int messageArgA;
    int messageArgB;
    ECSHShrinePuzzleScratch* puzzle;
    ECSHShrineState* state;
    GameObject* player;
    u8 byteValue;
    int shufflePattern;
    int cupIndex;
    s16 swapSlot;
    f32 zero;
    f32 timerValue;

    puzzle = (ECSHShrinePuzzleScratch*)gECSHShrineCupPositions;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    *(ECSHShrineWordPair*)&cupPositionSwap[0] = *(ECSHShrineWordPair*)(void*)&lbl_803E8470;
    if (state->introTextLatch == 0) {
        byteValue = mainGetBit(GAMEBIT_K1_SHRINE_INTRO_TEXT_TRIGGER);
        state->introTextLatch = byteValue;
        if (state->introTextLatch != 0) {
            (*gGameUIInterface)
                ->showNpcDialogue(ECSH_SHRINE_DIALOGUE_ID, ECSH_SHRINE_DIALOGUE_UNUSED_A, ECSH_SHRINE_DIALOGUE_UNUSED_B,
                                  ECSH_SHRINE_DIALOGUE_DISABLE_INPUT);
        }
    }
    if (obj->userData1 != 0) {
        obj->userData1 = obj->userData1 - 1;
        if (obj->userData1 == 0) {
            skySetSlotFlag80(ECSH_SHRINE_SKY_FLAGS, 1);
            getEnvfxAct(obj, player, ECSH_SHRINE_ENVFX_A, ECSH_SHRINE_ENVFX_FLAGS);
            getEnvfxAct(obj, player, ECSH_SHRINE_ENVFX_B, ECSH_SHRINE_ENVFX_FLAGS);
            getEnvfxAct(obj, player, ECSH_SHRINE_ENVFX_C, ECSH_SHRINE_ENVFX_FLAGS);
        }
    }
    ecshShrine_updateHoverMotion(obj);
    if (player != NULL && objIsCurModelNotZero(player) == 0) {
        staffToggle(player, ECSH_SHRINE_STAFF_DISABLED);
    }
    messageArgC = 0;
    while (ObjMsg_Pop(obj, (u32*)&messageArgA, (u32*)&messageArgB, (u32*)&messageArgC) != 0) {
    }
    GameBitLatch_Update(&state->gameBitLatch, ECSH_SHRINE_STATE_FLAG_TEST_RUNNING, ECSH_SHRINE_NO_GAMEBIT,
                        ECSH_SHRINE_NO_GAMEBIT, GAMEBIT_ECSH_TestObservRunning, MUSICTRIG_krazoa_doors_open);
    GameBitLatch_UpdateInverted(&state->gameBitLatch, ECSH_SHRINE_STATE_FLAG_MUSIC_LATCH_01, ECSH_SHRINE_NO_GAMEBIT,
                                ECSH_SHRINE_NO_GAMEBIT, GAMEBIT_SHRINE_MUSIC_LOCK, MUSICTRIG_vfp_walkabout);
    GameBitLatch_Update(&state->gameBitLatch, ECSH_SHRINE_STATE_FLAG_MUSIC_LATCH_10, ECSH_SHRINE_NO_GAMEBIT,
                        ECSH_SHRINE_NO_GAMEBIT, GAMEBIT_SHRINE_MUSIC_LOCK, MUSICTRIG_PU3_Adventure_c4);
    if (state->cooldownTimer > (zero = 0.0f)) {
        state->cooldownTimer = state->cooldownTimer - timeDelta;
        if (state->cooldownTimer <= zero) {
            state->cooldownTimer = zero;
        }
    } else {
        switch (state->testPhase) {
        case ECSH_SHRINE_PHASE_IDLE:
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            timerValue = state->voiceTimer - timeDelta;
            state->voiceTimer = timerValue;
            if (timerValue <= zero) {
                Sfx_PlayFromObject(obj, SFXTRIG_spirit_voice);
                state->voiceTimer = (f32)randomGetRange(ECSH_SHRINE_VOICE_DELAY_MIN, ECSH_SHRINE_VOICE_DELAY_MAX);
            }
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
                state->testPhase = ECSH_SHRINE_PHASE_INTRO_TRANSITION;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 0);
                (*gObjectTriggerInterface)->runSequence(ECSH_SHRINE_SEQUENCE_INTRO, obj, ECSH_SHRINE_SEQUENCE_FLAGS);
                Music_Trigger(MUSICTRIG_DIM_Snow, 1);
                {
                    f32 fz = 0.0f;
                    puzzle->cupPositions[0] = fz;
                    puzzle->cupPositions[1] = fz;
                    puzzle->cupPositions[2] = fz;
                    puzzle->cupPositions[3] = fz;
                    puzzle->cupPositions[4] = fz;
                    puzzle->cupPositions[5] = fz;
                    puzzle->cupPositions[6] = fz;
                    puzzle->cupPositions[7] = fz;
                    puzzle->cupPositions[8] = fz;
                    puzzle->cupPositions[9] = fz;
                    puzzle->cupPositions[10] = fz;
                    puzzle->cupPositions[11] = fz;
                }
                puzzle->cupSlotMap[0] = puzzle->nextCupSlotMap[0];
                puzzle->cupSlotMap[1] = puzzle->nextCupSlotMap[1];
                puzzle->cupSlotMap[2] = puzzle->nextCupSlotMap[2];
                puzzle->cupSlotMap[3] = puzzle->nextCupSlotMap[3];
                puzzle->cupSlotMap[4] = puzzle->nextCupSlotMap[4];
                puzzle->cupSlotMap[5] = puzzle->nextCupSlotMap[5];
                /* Reads the first halfword of the adjacent descriptor at 0x48. */
                puzzle->nextCupSlotMap[0] = *(s16*)((u8*)puzzle + sizeof(ECSHShrinePuzzleScratch));
            }
            break;
        case ECSH_SHRINE_PHASE_INTRO_TRANSITION:
            if (state->transitionReady == 1) {
                state->testPhase = ECSH_SHRINE_PHASE_PREPARE_ROUND_ONE;
                state->cooldownTimer = ECSH_SHRINE_INTRO_COOLDOWN;
                state->animState = 6;
                Sfx_PlayFromObject(obj, SFXTRIG_iceywindlp16);
                state->animTimer = 0.0f;
                mainSetBits(GAMEBIT_ECSH_TestObservRunning, 1);
                (*gScreenTransitionInterface)->step(ECSH_SHRINE_INTRO_TRANSITION_FRAMES, SCREEN_TRANSITION_BLACK);
            }
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            break;
        case ECSH_SHRINE_PHASE_PREPARE_ROUND_ONE:
            state->testPhase = ECSH_SHRINE_PHASE_ROUND_ONE;
            state->cooldownTimer = ECSH_SHRINE_ROUND_START_COOLDOWN;
            state->animState = 8;
            state->animTimer = ECSH_SHRINE_SHUFFLE_ANIM_TIMER;
            state->shuffleCount = ECSH_SHRINE_ROUND_ONE_SHUFFLES;
            byteValue = randomGetRange(0, ECSH_SHRINE_LAST_CUP_INDEX);
            state->spiritCup = byteValue;
            (*gObjectTriggerInterface)->runSequence(ECSH_SHRINE_SEQUENCE_ROUND, obj, ECSH_SHRINE_SEQUENCE_FLAGS);
            break;
        case ECSH_SHRINE_PHASE_ROUND_ONE:
        case ECSH_SHRINE_PHASE_ROUND_TWO:
        case ECSH_SHRINE_PHASE_ROUND_THREE:
            if (state->animTimer > (timerValue = 0.0f)) {
                if (state->animState == 1 && state->shuffleSfxPlayed == 0 &&
                    state->animTimer < state->shuffleSfxThreshold) {
                    if (randomGetRange(0, ECSH_SHRINE_SHUFFLE_SFX_ROLL_MAX) > ECSH_SHRINE_SHUFFLE_SFX_ROLL_THRESHOLD) {
                        Sfx_PlayFromObject(obj, SFXTRIG_spirit_voice_var);
                    }
                    state->shuffleSfxPlayed = 1;
                }
                state->animTimer = state->animTimer - timeDelta;
                if (state->animTimer < 0.0f) {
                    state->animTimer = 0.0f;
                }
            } else {
                switch (state->animState) {
                case 8:
                    state->animState = 2;
                    state->animTimer = ECSH_SHRINE_SHUFFLE_ANIM_TIMER;
                    state->cooldownTimer = ECSH_SHRINE_SHUFFLE_COOLDOWN;
                    break;
                case 9:
                    state->animState = 8;
                    state->animTimer = ECSH_SHRINE_SHUFFLE_ANIM_TIMER;
                    state->cooldownTimer = ECSH_SHRINE_SHUFFLE_COOLDOWN;
                    break;
                case 7:
                    state->animState = 3;
                    state->animTimer = ECSH_SHRINE_SHUFFLE_ANIM_TIMER;
                    state->cooldownTimer = ECSH_SHRINE_SHUFFLE_COOLDOWN;
                    break;
                case 2:
                    state->shuffleCount -= 1;
                    if (state->shuffleCount <= 0) {
                        Sfx_PlayFromObject(0, SFXTRIG_commsbleep);
                        state->animState = 5;
                        if (state->testPhase == ECSH_SHRINE_PHASE_ROUND_ONE) {
                            state->guessTimer = ECSH_SHRINE_GUESS_TIMER;
                        } else if (state->testPhase == ECSH_SHRINE_PHASE_ROUND_TWO) {
                            state->guessTimer = ECSH_SHRINE_GUESS_TIMER;
                        } else {
                            state->guessTimer = ECSH_SHRINE_GUESS_TIMER;
                        }
                    } else {
                        state->shuffleSfxPlayed = 0;
                        state->shuffleSfxThreshold =
                            (f32)randomGetRange(ECSH_SHRINE_SHUFFLE_SFX_DELAY_MIN, ECSH_SHRINE_SHUFFLE_SFX_DELAY_MAX);
                        Sfx_PlayFromObject(obj, SFXTRIG_spirit_basketspin);
                        state->animState = 0;
                        state->animTimer = ECSH_SHRINE_SHUFFLE_START_TIMER;
                        if (state->testPhase == ECSH_SHRINE_PHASE_ROUND_ONE) {
                            shufflePattern = randomGetRange(0, ECSH_SHRINE_ROUND_ONE_PATTERN_MAX);
                        } else if (state->testPhase == ECSH_SHRINE_PHASE_ROUND_TWO) {
                            shufflePattern = randomGetRange(0, ECSH_SHRINE_ROUND_TWO_PATTERN_MAX);
                        } else {
                            shufflePattern = randomGetRange(0, ECSH_SHRINE_ROUND_THREE_PATTERN_MAX);
                        }
                        if (shufflePattern == 0) {
                            for (cupIndex = 0; cupIndex < ECSH_SHRINE_CUP_COUNT; cupIndex++) {
                                puzzle->cupSlotMap[cupIndex] += 1;
                                if (puzzle->cupSlotMap[cupIndex] > ECSH_SHRINE_LAST_CUP_INDEX) {
                                    puzzle->cupSlotMap[cupIndex] = 0;
                                }
                            }
                        } else if (shufflePattern == 1) {
                            for (cupIndex = 0; cupIndex < ECSH_SHRINE_CUP_COUNT; cupIndex++) {
                                puzzle->cupSlotMap[cupIndex] -= 1;
                                if (puzzle->cupSlotMap[cupIndex] < 0) {
                                    puzzle->cupSlotMap[cupIndex] = 5;
                                }
                            }
                        } else if (shufflePattern == 2) {
                            swapSlot = puzzle->cupSlotMap[0];
                            puzzle->cupSlotMap[0] = puzzle->cupSlotMap[2];
                            puzzle->cupSlotMap[2] = puzzle->cupSlotMap[4];
                            puzzle->cupSlotMap[4] = swapSlot;
                        } else if (shufflePattern == 3) {
                            swapSlot = puzzle->cupSlotMap[4];
                            puzzle->cupSlotMap[4] = puzzle->cupSlotMap[0];
                            puzzle->cupSlotMap[0] = puzzle->cupSlotMap[2];
                            puzzle->cupSlotMap[2] = swapSlot;
                        } else if (shufflePattern == 4) {
                            swapSlot = puzzle->cupSlotMap[1];
                            puzzle->cupSlotMap[1] = puzzle->cupSlotMap[3];
                            puzzle->cupSlotMap[3] = puzzle->cupSlotMap[5];
                            puzzle->cupSlotMap[5] = swapSlot;
                        } else if (shufflePattern == 5) {
                            swapSlot = puzzle->cupSlotMap[5];
                            puzzle->cupSlotMap[5] = puzzle->cupSlotMap[1];
                            puzzle->cupSlotMap[1] = puzzle->cupSlotMap[3];
                            puzzle->cupSlotMap[3] = swapSlot;
                        } else if (shufflePattern == 6) {
                            cupPositionSwap[0] = puzzle->cupPositions[2];
                            cupPositionSwap[1] = puzzle->cupPositions[3];
                            puzzle->cupPositions[2] = puzzle->cupPositions[4];
                            puzzle->cupPositions[3] = puzzle->cupPositions[5];
                            puzzle->cupPositions[4] = puzzle->cupPositions[8];
                            puzzle->cupPositions[5] = puzzle->cupPositions[9];
                            puzzle->cupPositions[8] = puzzle->cupPositions[10];
                            puzzle->cupPositions[9] = puzzle->cupPositions[11];
                            puzzle->cupPositions[10] = cupPositionSwap[0];
                            puzzle->cupPositions[11] = cupPositionSwap[1];
                        } else if (shufflePattern == 7) {
                            cupPositionSwap[0] = puzzle->cupPositions[10];
                            cupPositionSwap[1] = puzzle->cupPositions[11];
                            puzzle->cupPositions[10] = puzzle->cupPositions[8];
                            puzzle->cupPositions[11] = puzzle->cupPositions[9];
                            puzzle->cupPositions[8] = puzzle->cupPositions[4];
                            puzzle->cupPositions[9] = puzzle->cupPositions[5];
                            puzzle->cupPositions[4] = puzzle->cupPositions[2];
                            puzzle->cupPositions[5] = puzzle->cupPositions[3];
                            puzzle->cupPositions[2] = cupPositionSwap[0];
                            puzzle->cupPositions[3] = cupPositionSwap[1];
                        }
                    }
                    break;
                case 0:
                    state->animState = 1;
                    state->animTimer = ECSH_SHRINE_SHUFFLE_MOVE_TIMER;
                    break;
                case 1:
                    state->animState = 4;
                    state->animTimer = timerValue;
                    break;
                case 4:
                    state->animState = 2;
                    state->animTimer = timerValue;
                    break;
                case 5:
                    Sfx_KeepAliveLoopedObjectSound(0, SFXTRIG_commsbleep);
                    if (state->matchFlag == 0) {
                        (*gScreenTransitionInterface)
                            ->start(ECSH_SHRINE_RESULT_TRANSITION_FRAMES, SCREEN_TRANSITION_BLACK);
                        state->cooldownTimer = ECSH_SHRINE_RESULT_COOLDOWN;
                        state->animState = 7;
                        Sfx_PlayFromObject(obj, SFXTRIG_iceywindlp16);
                        state->testPhase = ECSH_SHRINE_PHASE_FAIL;
                    } else if (state->matchFlag == 1) {
                        if (state->testPhase == ECSH_SHRINE_PHASE_ROUND_ONE) {
                            byteValue = randomGetRange(0, ECSH_SHRINE_LAST_CUP_INDEX);
                            state->spiritCup = byteValue;
                            state->testPhase = ECSH_SHRINE_PHASE_ROUND_TWO;
                            state->animState = 9;
                            state->cooldownTimer = ECSH_SHRINE_NEXT_ROUND_COOLDOWN;
                            state->animTimer = ECSH_SHRINE_NEXT_ROUND_ANIM_TIMER;
                            state->shuffleCount = ECSH_SHRINE_ROUND_TWO_SHUFFLES;
                            state->matchFlag = -1;
                            Sfx_PlayFromObject(obj, SFXTRIG_sc_menuups16k);
                            (*gObjectTriggerInterface)
                                ->runSequence(ECSH_SHRINE_SEQUENCE_ROUND, obj, ECSH_SHRINE_SEQUENCE_FLAGS);
                        } else if (state->testPhase == ECSH_SHRINE_PHASE_ROUND_TWO) {
                            byteValue = randomGetRange(0, ECSH_SHRINE_LAST_CUP_INDEX);
                            state->spiritCup = byteValue;
                            state->testPhase = ECSH_SHRINE_PHASE_ROUND_THREE;
                            state->animState = 9;
                            state->cooldownTimer = ECSH_SHRINE_NEXT_ROUND_COOLDOWN;
                            state->animTimer = ECSH_SHRINE_NEXT_ROUND_ANIM_TIMER;
                            state->shuffleCount = ECSH_SHRINE_ROUND_THREE_SHUFFLES;
                            state->matchFlag = -1;
                            Sfx_PlayFromObject(obj, SFXTRIG_sc_menuups16k);
                            (*gObjectTriggerInterface)
                                ->runSequence(ECSH_SHRINE_SEQUENCE_ROUND, obj, ECSH_SHRINE_SEQUENCE_FLAGS);
                        } else {
                            state->cooldownTimer = ECSH_SHRINE_RESULT_COOLDOWN;
                            (*gScreenTransitionInterface)
                                ->start(ECSH_SHRINE_RESULT_TRANSITION_FRAMES, SCREEN_TRANSITION_BLACK);
                            state->testPhase = ECSH_SHRINE_PHASE_SUCCESS;
                            state->animState = 3;
                            state->matchFlag = 0;
                            state->animState = 7;
                            Sfx_PlayFromObject(obj, SFXTRIG_mpick1_b);
                            Sfx_PlayFromObject(obj, SFXTRIG_iceywindlp16);
                        }
                    } else {
                        state->guessTimer = state->guessTimer - timeDelta;
                        if (state->guessTimer <= 0.0f) {
                            state->testPhase = ECSH_SHRINE_PHASE_FAIL;
                            (*gScreenTransitionInterface)
                                ->start(ECSH_SHRINE_RESULT_TRANSITION_FRAMES, SCREEN_TRANSITION_BLACK);
                            state->cooldownTimer = ECSH_SHRINE_RESULT_COOLDOWN;
                            state->animState = 7;
                            Sfx_PlayFromObject(obj, SFXTRIG_iceywindlp16);
                        }
                    }
                    break;
                }
            }
            break;
        case ECSH_SHRINE_PHASE_FAIL:
            mainSetBits(ECSH_SHRINE_GAMEBIT_0A6F, 1);
            state->testPhase = ECSH_SHRINE_PHASE_RESET;
            break;
        case ECSH_SHRINE_PHASE_SUCCESS:
            mainSetBits(GAMEBIT_ECSH_TestObservRunning, 0);
            audioStopByMask(ECSH_SHRINE_AUDIO_STOP_MASK);
            if (objGetAnimStateFlags(player, ECSH_SHRINE_PLAYER_ANIM_STATE_FLAG) != 0) {
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                state->testPhase = ECSH_SHRINE_PHASE_POST_SUCCESS;
            } else {
                state->testPhase = ECSH_SHRINE_PHASE_POST_SUCCESS;
                (*gObjectTriggerInterface)->runSequence(ECSH_SHRINE_SEQUENCE_SUCCESS, obj, ECSH_SHRINE_SEQUENCE_FLAGS);
            }
            break;
        case ECSH_SHRINE_PHASE_POST_SUCCESS:
            mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 0);
            state->testPhase = ECSH_SHRINE_PHASE_RESET;
            break;
        case ECSH_SHRINE_PHASE_RESET:
            state->testPhase = ECSH_SHRINE_PHASE_IDLE;
            state->animTimer = zero;
            state->unknown20 = 0;
            state->shuffleCount = 0;
            state->animState = 0;
            state->matchFlag = -1;
            state->spiritCup = 0;
            state->transitionReady = 0;
            state->cooldownTimer = ECSH_SHRINE_RESET_COOLDOWN;
            mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
            mainSetBits(GAMEBIT_ECSH_TestObservRunning, 0);
            mainSetBits(ECSH_SHRINE_GAMEBIT_0A6D, 0);
            mainSetBits(ECSH_SHRINE_GAMEBIT_0A6F, 0);
            mainSetBits(ECSH_SHRINE_GAMEBIT_0A70, 0);
            mainSetBits(GAMEBIT_WM_Spirit1Related_0143, 0);
            state->transitionReady = 0;
            state->matchFlag = -1;
            break;
        }
    }
}

void ecshShrine_init(GameObject* obj, const s8* placement) {
    ECSHShrineState* state = obj->extra;
    u8 byteValue;

    lbl_803DDBC0 = 0;
    gECSHShrineActiveObject = NULL;
    obj->anim.rotX =
        (s16)((s32)placement[ECSH_SHRINE_PLACEMENT_ROTATION_OFFSET] << ECSH_SHRINE_PLACEMENT_ROTATION_SHIFT);
    state->testPhase = ECSH_SHRINE_PHASE_IDLE;
    state->transitionReady = 0;
    state->animTimer = 0.0f;
    state->unknown20 = 0;
    state->shuffleCount = 0;
    state->animState = 0;
    state->matchFlag = -1;
    state->spiritCup = 0;
    state->gameBitLatch.activeMask = 0;
    obj->animEventCallback = ecshShrine_processAnimEvents;
    ObjMsg_AllocQueue(obj, ECSH_SHRINE_MESSAGE_QUEUE_CAPACITY);
    mainSetBits(GAMEBIT_ECSH_Entered, 1);
    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
    mainSetBits(GAMEBIT_WM_Spirit1Related_0143, 0);
    state->unknown18 = ECSH_SHRINE_UNKNOWN_18_INITIAL;
    state->unknown1C = ECSH_SHRINE_UNKNOWN_1C_INITIAL;
    state->cooldownTimer = ECSH_SHRINE_INTRO_COOLDOWN;
    state->unknown1A = 0;
    state->unknown1E = 0;
    byteValue = mainGetBit(GAMEBIT_K1_SHRINE_INTRO_TEXT_TRIGGER);
    state->introTextLatch = byteValue;
    gECSHShrineActiveObject = obj;
    objAddObjectType(obj, ECSH_SHRINE_OBJECT_GROUP);
    obj->userData1 = ECSH_SHRINE_LOAD_TIMER_START;
    if (state->light == NULL) {
        state->light = objCreateLight(NULL, 1);
    }
    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 1);
}

void ecshShrine_release(void) {
}

void ecshShrine_initialise(void) {
}
