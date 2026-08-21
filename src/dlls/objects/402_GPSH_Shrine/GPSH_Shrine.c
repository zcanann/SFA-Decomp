/*
 * GPSH_Shrine (DLL 0x192) - Krazoa Shrine Test of Knowledge.
 *
 * Runs the timed six-symbol puzzle, the floating shrine model, and the
 * animation events that activate the test and grant its Krazoa Spirit.
 */
#include "dlls/objects/402_GPSH_Shrine.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "game/objects/object_setup.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/game_timer_control_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/map_load.h"
#include "main/mapEventTypes.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/objseq.h"
#include "main/pi_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/screen_transition.h"
#include "main/sky_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define GPSH_SHRINE_ENVFX_A 0xCC
#define GPSH_SHRINE_ENVFX_B 0xCD
#define GPSH_SHRINE_ENVFX_C 0x222

#define GPSH_SHRINE_OBJ_GROUP         0xB
#define GPSH_SHRINE_MAP_ID            0xB
#define GPSH_SHRINE_SPAWNED_OBJ_GROUP 0x10

#define GPSH_SHRINE_ORBIT_RATE_A         512.0f
#define GPSH_SHRINE_ORBIT_RATE_B         128.0f
#define GPSH_SHRINE_ORBIT_RATE_C         192.0f
#define GPSH_SHRINE_ORBIT_HEIGHT         20.0f
#define GPSH_SHRINE_ORBIT_ROTATION_SCALE 600.0f
#define GPSH_SHRINE_ANIMATION_STEP       0.005f
#define GPSH_SHRINE_TURN_RATE_DIVISOR    12.0f
#define GPSH_SHRINE_FADE_DISTANCE        30.0f
#define GPSH_SHRINE_FULL_ALPHA           255.0f
#define GPSH_SHRINE_ANGLE_HALF_TURN      0x8000
#define GPSH_SHRINE_ANGLE_WRAP           0xFFFF
#define GPSH_SHRINE_ORBIT_PI             3.1415927f
#define GPSH_SHRINE_ORBIT_ANGLE_SCALE    32768.0f

#define GPSH_SHRINE_PLAYER_ANIM_STATE_FLAG 0x80
#define GPSH_SHRINE_REWARD_MAP_ACT         5

enum {
    GPSH_SHRINE_ANIM_EVENT_ACTIVATE = 3,
    GPSH_SHRINE_ANIM_EVENT_GRANT_SPIRIT = 7,
    GPSH_SHRINE_ANIM_EVENT_LOCK_POSE = 14,
    GPSH_SHRINE_ANIM_EVENT_UNLOCK_POSE = 15,
};

typedef enum GPSHShrinePhase {
    GPSH_SHRINE_PHASE_IDLE = 0,
    GPSH_SHRINE_PHASE_WAIT_FOR_PUZZLE = 1,
    GPSH_SHRINE_PHASE_PUZZLE_ACTIVE = 2,
    GPSH_SHRINE_PHASE_SUCCESS = 3,
    GPSH_SHRINE_PHASE_RESET = 4,
    GPSH_SHRINE_PHASE_BEGIN = 5,
    GPSH_SHRINE_PHASE_SUCCESS_TRANSITION = 6,
    GPSH_SHRINE_PHASE_FAIL_TRANSITION = 7,
} GPSHShrinePhase;

ObjectDescriptor gGPSHShrineObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)gpshShrine_initialise,
    (ObjectDescriptorCallback)gpshShrine_release,
    0,
    (ObjectDescriptorCallback)gpshShrine_init,
    (ObjectDescriptorCallback)gpshShrine_update,
    (ObjectDescriptorCallback)gpshShrine_hitDetect,
    (ObjectDescriptorCallback)gpshShrine_render,
    (ObjectDescriptorCallback)gpshShrine_free,
    (ObjectDescriptorCallback)gpshShrine_getObjectTypeId,
    gpshShrine_getExtraSize,
};

void gpshShrine_updateHoverMotion(GameObject* obj) {
    const ObjPlacement* placement;
    GPSHShrineState* state;
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

    state->orbitPhaseA += (s32)(GPSH_SHRINE_ORBIT_RATE_A * timeDelta);
    state->orbitPhaseB += (s32)(GPSH_SHRINE_ORBIT_RATE_B * timeDelta);
    state->orbitPhaseC += (s32)(GPSH_SHRINE_ORBIT_RATE_C * timeDelta);

    obj->anim.localPosY =
        GPSH_SHRINE_ORBIT_HEIGHT +
        (placement->posY + mathSinf((GPSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / GPSH_SHRINE_ORBIT_ANGLE_SCALE));

    trigA = mathSinf((GPSH_SHRINE_ORBIT_PI * state->orbitPhaseB) / GPSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = mathSinf((GPSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / GPSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB += trigA;
    obj->anim.rotZ = GPSH_SHRINE_ORBIT_ROTATION_SCALE * trigB;

    trigA = mathSinf((GPSH_SHRINE_ORBIT_PI * state->orbitPhaseC) / GPSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB = mathSinf((GPSH_SHRINE_ORBIT_PI * state->orbitPhaseA) / GPSH_SHRINE_ORBIT_ANGLE_SCALE);
    trigB += trigA;
    obj->anim.rotY = GPSH_SHRINE_ORBIT_ROTATION_SCALE * trigB;

    ObjAnim_AdvanceCurrentMove(obj, GPSH_SHRINE_ANIMATION_STEP, timeDelta, &animEvents);

    if (player != NULL) {
        angleDelta =
            (u16)getAngle(obj->anim.worldPosX - player->anim.worldPosX, obj->anim.worldPosZ - player->anim.worldPosZ) -
            (u16)obj->anim.rotX;
        if (angleDelta > GPSH_SHRINE_ANGLE_HALF_TURN) {
            angleDelta -= GPSH_SHRINE_ANGLE_WRAP;
        }
        if (angleDelta < -GPSH_SHRINE_ANGLE_HALF_TURN) {
            angleDelta += GPSH_SHRINE_ANGLE_WRAP;
        }

        obj->anim.rotX =
            (s16)(*(s16*)(int)&obj->anim.rotX + (s32)(((f32)angleDelta * timeDelta) / GPSH_SHRINE_TURN_RATE_DIVISOR));
        distance = Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX);
        if (distance <= GPSH_SHRINE_FADE_DISTANCE) {
            obj->anim.alpha = (u8)(s32)(GPSH_SHRINE_FULL_ALPHA * (distance / GPSH_SHRINE_FADE_DISTANCE));
        } else {
            obj->anim.alpha = 0xFF;
        }
    }
}

int gpshShrine_processAnimEvents(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    GPSHShrineState* state;
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
            case GPSH_SHRINE_ANIM_EVENT_ACTIVATE:
                state->puzzleFlags.activated = 1;
                break;
            case GPSH_SHRINE_ANIM_EVENT_GRANT_SPIRIT:
                objSetAnimStateFlags(player, GPSH_SHRINE_PLAYER_ANIM_STATE_FLAG, 1);
                mainSetBits(0x12b, 1);
                mainSetBits(GAMEBIT_ITEM_Spirit5_Got, 1);
                (*gMapEventInterface)->setMapAct(GPSH_SHRINE_MAP_ID, GPSH_SHRINE_REWARD_MAP_ACT);
                break;
            case GPSH_SHRINE_ANIM_EVENT_LOCK_POSE:
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                if (state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, 0, 1.0f);
                }
                break;
            case GPSH_SHRINE_ANIM_EVENT_UNLOCK_POSE:
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

int gpshShrine_getExtraSize(void) {
    return sizeof(GPSHShrineState);
}

int gpshShrine_getObjectTypeId(void) {
    return 0;
}

void gpshShrine_free(GameObject* obj) {
    GPSHShrineState* state = obj->extra;

    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    gameTimerStop();
    objFreeObjectType(obj, GPSH_SHRINE_OBJ_GROUP);
    Music_Trigger(MUSICTRIG_DIM_Snow, 0);
    Music_Trigger(MUSICTRIG_CC_Visit1, 0);
    Music_Trigger(MUSICTRIG_vfp_walkabout, 0);
    Music_Trigger(MUSICTRIG_krazoa_tunnel_2, 0);
    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 0);
    mainSetBits(GAMEBIT_SHRINE_MUSIC_LOCK, mainGetBit(0xc91) == 0);
}

void gpshShrine_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    GPSHShrineState* state = obj->extra;

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

void gpshShrine_hitDetect(void) {
}

void gpshShrine_update(GameObject* obj) {
    int objectCount;
    GPSHShrineState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();
    u8 gameBit0149;
    u8 gameBit014C;
    u8 gameBit014D;
    u8 gameBit014E;
    u8 gameBit014A;
    u8 gameBit014B;
    GameObject** objects;
    f32 idleSfxTimer;
    f32 zero;

    objectCount = 0;
    if (player != NULL) {
        gameBit0149 = mainGetBit(0x149);
        gameBit014C = mainGetBit(0x14c);
        gameBit014D = mainGetBit(0x14d);
        gameBit014E = mainGetBit(0x14e);
        gameBit014A = mainGetBit(0x14a);
        gameBit014B = mainGetBit(0x14b);
        if (gameBit0149 == 0 || gameBit014C == 0 || gameBit014D == 0 || gameBit014E == 0 || gameBit014A == 0 ||
            gameBit014B == 0) {
            if (!state->puzzleFlags.gameBit0149Latched && gameBit0149 != 0) {
                state->puzzleFlags.gameBit0149Latched = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            } else if (!state->puzzleFlags.gameBit014CLatched && gameBit014C != 0) {
                state->puzzleFlags.gameBit014CLatched = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            } else if (!state->puzzleFlags.gameBit014DLatched && gameBit014D != 0) {
                state->puzzleFlags.gameBit014DLatched = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            } else if (!state->puzzleFlags.gameBit014ELatched && gameBit014E != 0) {
                state->puzzleFlags.gameBit014ELatched = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            } else if (!state->puzzleFlags.gameBit014ALatched && gameBit014A != 0) {
                state->puzzleFlags.gameBit014ALatched = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            } else if (!state->puzzleFlags.gameBit014BLatched && gameBit014B != 0) {
                state->puzzleFlags.gameBit014BLatched = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
        }

        if (obj->userData1 != 0) {
            obj->userData1 -= 1;
            if (obj->userData1 == 0) {
                skySetSlotFlag80(7, 1);
                getEnvfxAct(obj, player, GPSH_SHRINE_ENVFX_A, 0);
                getEnvfxAct(obj, player, GPSH_SHRINE_ENVFX_B, 0);
                getEnvfxAct(obj, player, GPSH_SHRINE_ENVFX_C, 0);
            }
        }

        gpshShrine_updateHoverMotion(obj);
        unlockLevel(mapGetDirIdx(0x22), 1, 0);

        /* This engine latch intentionally overlaps the shrine's phase and flags. */
        GameBitLatch_Update((GameBitLatchState*)state->gameBitLatchStorage, 2, -1, -1, 0xdd2, 0xb);
        GameBitLatch_UpdateInverted((GameBitLatchState*)state->gameBitLatchStorage, 1, -1, -1,
                                    GAMEBIT_SHRINE_MUSIC_LOCK, 8);
        GameBitLatch_Update((GameBitLatchState*)state->gameBitLatchStorage, 4, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK,
                            MUSICTRIG_PU3_Adventure_c4);

        if (state->phaseDelay > (zero = 0.0f)) {
            state->phaseDelay -= timeDelta;
            if (state->phaseDelay <= zero) {
                state->phaseDelay = zero;
            }
        } else {
            switch ((GPSHShrinePhase)state->phase) {
            case GPSH_SHRINE_PHASE_IDLE:
                obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                idleSfxTimer = state->idleSfxTimer - timeDelta;
                state->idleSfxTimer = idleSfxTimer;
                if (idleSfxTimer <= zero) {
                    Sfx_PlayFromObject(obj, SFXTRIG_spirit_voice);
                    state->idleSfxTimer = (f32)randomGetRange(500, 1000);
                }
                if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
                    state->phase = GPSH_SHRINE_PHASE_BEGIN;
                    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 0);
                    mainSetBits(GPSH_SHRINE_RESET_SYMBOL_CREATORS_GAMEBIT, 0);
                    mainSetBits(GAMEBIT_GPSH_TestKnowledgeRunning, 1);
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                    Music_Trigger(MUSICTRIG_DIM_Snow, 1);
                }
                break;
            case GPSH_SHRINE_PHASE_BEGIN:
                state->phaseDelay = 31.0f;
                (*gScreenTransitionInterface)->step(0x1e, SCREEN_TRANSITION_BLACK);
                state->phase = GPSH_SHRINE_PHASE_WAIT_FOR_PUZZLE;
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                break;
            case GPSH_SHRINE_PHASE_WAIT_FOR_PUZZLE:
                if (state->puzzleFlags.activated == 1) {
                    mainSetBits(GPSH_SHRINE_ACTIVATE_SYMBOL_SPAWNS_GAMEBIT, 1);
                    state->phase = GPSH_SHRINE_PHASE_PUZZLE_ACTIVE;
                    gameTimerInit(0x1d, 0x4e);
                    timerSetToCountUp();
                }
                break;
            case GPSH_SHRINE_PHASE_PUZZLE_ACTIVE:
                state->solvedCount = 0;
                if (mainGetBit(0x149)) {
                    state->solvedCount += 1;
                }
                if (mainGetBit(0x14b)) {
                    state->solvedCount += 1;
                }
                if (mainGetBit(0x14e)) {
                    state->solvedCount += 1;
                }
                if (mainGetBit(0x14d)) {
                    state->solvedCount += 1;
                }
                if (mainGetBit(0x14c)) {
                    state->solvedCount += 1;
                }
                if (mainGetBit(0x14a)) {
                    state->solvedCount += 1;
                }
                if (state->solvedCount == 6) {
                    state->phase = GPSH_SHRINE_PHASE_SUCCESS_TRANSITION;
                    gameTimerStop();
                    mainSetBits(GAMEBIT_GPSH_TestKnowledgeRunning, 0);
                    state->phaseDelay = 31.0f;
                    (*gScreenTransitionInterface)->start(0x1e, SCREEN_TRANSITION_BLACK);
                    Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
                } else if (isGameTimerDisabled()) {
                    state->phase = GPSH_SHRINE_PHASE_FAIL_TRANSITION;
                    objects = (GameObject**)objGetAllOfType(GPSH_SHRINE_SPAWNED_OBJ_GROUP, &objectCount);
                    for (; objectCount != 0; objectCount--) {
                        Obj_FreeObject(objects[objectCount - 1]);
                    }
                    state->phaseDelay = 31.0f;
                    (*gScreenTransitionInterface)->start(0x1e, SCREEN_TRANSITION_BLACK);
                } else {
                    state->solvedCount = 0;
                }
                break;
            case GPSH_SHRINE_PHASE_FAIL_TRANSITION:
                state->phase = GPSH_SHRINE_PHASE_RESET;
                mainSetBits(GAMEBIT_GPSH_TestKnowledgeRunning, 0);
                mainSetBits(0xe37, 1);
                break;
            case GPSH_SHRINE_PHASE_SUCCESS_TRANSITION:
                state->phase = GPSH_SHRINE_PHASE_SUCCESS;
                break;
            case GPSH_SHRINE_PHASE_SUCCESS:
                if (objGetAnimStateFlags(player, GPSH_SHRINE_PLAYER_ANIM_STATE_FLAG)) {
                    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                    state->phase = GPSH_SHRINE_PHASE_RESET;
                } else {
                    audioStopByMask(3);
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    state->phase = GPSH_SHRINE_PHASE_RESET;
                    mainSetBits(GAMEBIT_WC_ObjGroups, 0);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, 0, 1);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, 1, 1);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, 5, 1);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, 10, 1);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, GPSH_SHRINE_OBJ_GROUP, 1);
                    mainSetBits(0xc91, 1);
                    mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 0);
                }
                break;
            case GPSH_SHRINE_PHASE_RESET:
                state->phase = GPSH_SHRINE_PHASE_IDLE;
                state->puzzleFlags.activated = 0;
                mainSetBits(GAMEBIT_GPSH_TestKnowledgeRunning, 0);
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                mainSetBits(0x149, 0);
                mainSetBits(0x14c, 0);
                mainSetBits(0x14d, 0);
                mainSetBits(0x14e, 0);
                mainSetBits(0x14a, 0);
                mainSetBits(0x14b, 0);
                mainSetBits(0x14b, 0);
                mainSetBits(GPSH_SHRINE_RESET_SYMBOL_CREATORS_GAMEBIT, 1);
                mainSetBits(GPSH_SHRINE_ACTIVATE_SYMBOL_SPAWNS_GAMEBIT, 0);
                mainSetBits(0xe37, 0);
                mainSetBits(0xe3a, 0);
                state->puzzleFlags.gameBit0149Latched = 0;
                state->puzzleFlags.gameBit014CLatched = 0;
                state->puzzleFlags.gameBit014DLatched = 0;
                state->puzzleFlags.gameBit014ELatched = 0;
                state->puzzleFlags.gameBit014ALatched = 0;
                state->puzzleFlags.gameBit014BLatched = 0;
                break;
            }
        }
    }
}

void gpshShrine_init(GameObject* obj, const void* placement) {
    GPSHShrineState* state;

    (void)placement;
    state = obj->extra;
    obj->anim.rotX = 0;
    obj->animEventCallback = gpshShrine_processAnimEvents;
    obj->anim.worldPosX = obj->anim.localPosX;
    obj->anim.worldPosY = obj->anim.localPosY;
    obj->anim.worldPosZ = obj->anim.localPosZ;
    state->phase = GPSH_SHRINE_PHASE_IDLE;
    state->puzzleFlags.activated = 0;
    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
    mainSetBits(0x12b, 0);
    mainSetBits(0x149, 0);
    mainSetBits(0x14c, 0);
    mainSetBits(0x14d, 0);
    mainSetBits(0x14e, 0);
    mainSetBits(0x14a, 0);
    mainSetBits(0x14b, 0);
    obj->userData1 = 1;
    if (state->light == NULL) {
        state->light = objCreateLight(NULL, 1);
    }
    mainSetBits(GAMEBIT_WC_EnteredShrine, 1);
    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 1);
}

void gpshShrine_release(void) {
}

void gpshShrine_initialise(void) {
}
