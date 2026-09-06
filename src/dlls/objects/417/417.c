#include "dlls/objects/417_NW_mammoth.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dlls/objects/209_TumbleWeedB.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/curve.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "dlls/objects/196_Tricky.h"
#include "dlls/objects/201_Baddie.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/player_target.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/newshadows_audio_api.h"
#include "main/objtype.h"
#include "main/obj_path.h"
#include "main/obj_trigger.h"
#include "main/object_render.h"
#include "main/objHitReact.h"
#include "main/objprint_api.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/objprint_character_api.h"

typedef struct NwMammothPathParams {
    u8 values[4];
} NwMammothPathParams;

typedef struct NwMammothTables {
    ObjHitReactEntry normalHitReactEntry;
    ObjHitReactEntry heavyHitReactEntry;
    u8 unknown28[0x68 - 0x28];
    s16 stateMoveIds[NW_MAMMOTH_STATE_COUNT];
    f32 stateMoveStepScales[0x17];
    u8 stateFlags[NW_MAMMOTH_STATE_COUNT];
} NwMammothTables;

STATIC_ASSERT(sizeof(NwMammothTables) == 0x10C);
STATIC_ASSERT(offsetof(NwMammothTables, stateMoveIds) == 0x68);
STATIC_ASSERT(offsetof(NwMammothTables, stateMoveStepScales) == 0x98);
STATIC_ASSERT(offsetof(NwMammothTables, stateFlags) == 0xF4);

static const NwMammothPathParams sNwMammothPathParams = {{1, 1, 1, 1}};

u8 gNwMammothFeedIntroTriggerList[4] = {1, 0, 0, 0};
u8 gNwMammothFeedFirstRootTriggerList[4] = {1, 1, 0, 0};
u8 gNwMammothFeedSecondRootTriggerList[4] = {1, 3, 0, 0};
u8 gNwMammothFeedSatisfiedTriggerList[4] = {1, 5, 0, 0};
u8 gNwMammothMode1DefaultTriggerList[4] = {2, 0, 1, 0};
u8 gNwMammothMode1TrickyDistractTriggerList[4] = {2, 3, 4, 0};
u8 gNwMammothMode1RescuedTriggerList[4] = {3, 2, 3, 4};
u8 gNwMammothMode1ArtifactObtainedTriggerList[4] = {2, 5, 6, 0};
u8 gNwMammothMode1ArtifactCompleteTriggerList[4] = {1, 7, 0, 0};
u8 gNwMammothPatrolDefaultTriggerList[4] = {2, 8, 9, 0};
u8 gNwMammothPatrolTrickyDistractTriggerList[4] = {3, 0x0A, 0x0B, 0x0C};
u8 gNwMammothPatrolRescuedTriggerList[4] = {2, 0x0B, 0x0C, 0};
u8 gNwMammothPatrolArtifactObtainedTriggerList[4] = {2, 0x0D, 0x0E, 0};
u8 gNwMammothPatrolArtifactCompleteTriggerList[4] = {1, 0x0F, 0, 0};
u8 gNwMammothGatekeeperCollectionTriggerList[4] = {2, 0, 1, 0};
u8 gNwMammothGatekeeperDefaultTriggerList[4] = {2, 2, 3, 0};
u8 gNwMammothGatekeeperBit224TriggerList[4] = {1, 4, 0, 0};
u8 gNwMammothArtifactPromptTriggerList[4] = {1, 0, 0, 0};
u8 gNwMammothArtifactCollectedTriggerList[4] = {1, 1, 0, 0};
u8 gNwMammothArtifactCompleteTriggerList[4] = {1, 2, 0, 0};

#define NW_MAMMOTH_PARTFX                 0x7F0
#define NW_MAMMOTH_TARGET_OBJECT_GROUP    0xF
#define NW_MAMMOTH_AIR_METER_MAX_VALUE    0xC8
#define NW_MAMMOTH_AIR_METER_BG_TEXTURE   0x5D0
#define NW_MAMMOTH_GROUP_ID               0x4D
#define NW_MAMMOTH_PATH_SETUP_POINT_COUNT 4
#define NW_MAMMOTH_TRIGGER_RANDOM_MIN     1
#define NW_MAMMOTH_CURVE_PARAM            0x19

typedef struct NwMammothTumbleweedInterface {
    void* pad00[11];
    void (*startHoming)(GameObject* tumbleweed, f32* targetPos);
    int (*isHoming)(GameObject* tumbleweed);
} NwMammothTumbleweedInterface;

STATIC_ASSERT(offsetof(NwMammothTumbleweedInterface, startHoming) == 0x2C);
STATIC_ASSERT(offsetof(NwMammothTumbleweedInterface, isHoming) == 0x30);

enum NwMammothRuntimeFlag {
    NW_MAMMOTH_RUNTIME_PATH_CONTROL = 0x01,
    NW_MAMMOTH_RUNTIME_ANIM_ENDED = 0x02,
    NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_RUNTIME_MENU_LOCK = 0x10,
    NW_MAMMOTH_RUNTIME_RESET_PATH = 0x20,
    NW_MAMMOTH_RUNTIME_UI_MESSAGE = 0x40,
};

enum NwMammothStateFlag {
    NW_MAMMOTH_STATE_FLAG_PATH_CONTROL = 0x01,
    NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT = 0x02,
    NW_MAMMOTH_STATE_FLAG_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT = 0x08,
    NW_MAMMOTH_STATE_FLAG_MENU_ACTION = 0x10,
    NW_MAMMOTH_STATE_FLAG_SOLID = 0x20,
};

u8 gNwMammothHitReactEntriesData[40] = {
    0x02, 0xDA, 0x03, 0x75, 0x00, 0x30, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x44,
    0x9B, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x02, 0xDA, 0x03, 0x75, 0x00, 0x31, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x3C, 0x44, 0x9B, 0xA6, 0x00, 0x00, 0x00, 0x00,
};

f32 gNwMammothPathSetupDataA[12] = {-12.0f, 0.0f, -20.0f, 12.0f, 0.0f, -20.0f, 12.0f, 0.0f, 20.0f, -12.0f, 0.0f, 20.0f};

u8 gNwMammothPathSetupDataB[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x25,
    0x00, 0x24, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x29, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A,
    0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3,
    0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x3B, 0xA3, 0xD7, 0x0A, 0xBC, 0x23, 0xD7, 0x0A,
    0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3C, 0x03,
    0x12, 0x6F, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A,
    0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0x44, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6,
};

u8 gNwMammothStateFlags[NW_MAMMOTH_STATE_COUNT] = {0x04, 0x14, 0x14, 0x04, 0x14, 0x04, 0x04, 0x04,
                                                   0x00, 0x29, 0x29, 0x28, 0x28, 0x28, 0x29, 0x29,
                                                   0x29, 0x29, 0x29, 0x04, 0x09, 0x03, 0x09, 0x00};
int gNwMammothRescueBushObjectIds[4] = {0x4ABDA, 0x4ABDB, 0x4ABDC, 0x4ABDD};
int gNwMammothRescueBushClearedGameBits[4] = {
    GAMEBIT_NW_RescueBush1Cleared,
    GAMEBIT_NW_RescueBush2Cleared,
    GAMEBIT_NW_RescueBush3Cleared,
    GAMEBIT_NW_RescueBush4Cleared,
};

ObjectDescriptor gNW_mammothObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)NW_mammoth_init,
    (ObjectDescriptorCallback)NW_mammoth_update,
    0,
    (ObjectDescriptorCallback)NW_mammoth_render,
    (ObjectDescriptorCallback)NW_mammoth_free,
    0,
    NW_mammoth_getExtraSize,
};

f32* NW_mammoth_getSpawnPosition(GameObject* obj) {
    return &((NwMammothState*)obj->extra)->spawnPosX;
}

int NW_mammoth_processAnimEvents(GameObject* obj, int unusedArg, ObjSeqState* animUpdate) {
    NwMammothState* state;
    void* audioEvents;
    void* audioPoints;
    void* audioScratch;

    (void)unusedArg;
    state = (NwMammothState*)obj->extra;
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_RESET_PATH) == 0) {
        Sfx_StopObjectChannel(obj, 0x7f);
        state->pathSpeed = 0.0f;
        state->runtimeFlags = state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_MENU_LOCK;
        state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_RESET_PATH;
    }
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH) != 0) {
        state->playerDistanceSq = 0.0f;
        animUpdate->flags = animUpdate->flags & ~8;
        animUpdate->flags = animUpdate->flags & ~0x40;
        NW_mammoth_updateEyeTracking(obj, state, 1);
    }
    audioEvents = &state->animEvents;
    audioPoints = state->pathPoints;
    audioScratch = &state->pathState;
    objAudioDispatchAnimEvents(obj, (ObjAnimEventList*)audioEvents, 8, audioPoints, audioScratch, 1.0f, 1.0f);
    if (animUpdate->eventCount != 0) {
        obj->objectFlags = (u16)(obj->objectFlags & ~OBJECT_OBJFLAG_SHADOW_DISABLED);
        obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
    }
    return 0;
}

void NW_mammoth_updateEyeTracking(GameObject* obj, NwMammothState* state, int enabled) {
    if (enabled != 0 && state->playerObject != NULL && state->playerDistanceSq < 40000.0f) {
        state->eyeAnim.lookAtActive = 1;
        state->eyeAnim.lookAtPosX = state->playerObject->anim.localPosX;
        state->eyeAnim.lookAtPosY = state->playerObject->anim.localPosY;
        state->eyeAnim.lookAtPosZ = state->playerObject->anim.localPosZ;
    } else {
        state->eyeAnim.lookAtActive = 0;
    }
    if ((gNwMammothStateFlags[state->stateIndex] & NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT) != 0) {
        characterHeadLookRelax(obj, &state->eyeAnim);
        characterCloseEyes(obj, &state->eyeAnim);
    } else {
        characterUpdateHeadLook(obj, &state->eyeAnim, 0.0f);
        characterDoEyeAnims(obj, &state->eyeAnim);
    }
}

int NW_mammoth_updateSleepCycle(GameObject* obj, NwMammothState* state);
void NW_mammoth_updateGatekeeper(GameObject* obj, NwMammothState* state, NwMammothPlacement* placement);
void NW_mammoth_updatePatrol(GameObject* obj, NwMammothState* state, NwMammothPlacement* placement);
void NW_mammoth_updateArtifactQuest(GameObject* obj, NwMammothState* state, NwMammothPlacement* placement);
void NW_mammoth_updateFeedQuest(GameObject* obj, NwMammothState* state, NwMammothPlacement* placement);

int NW_mammoth_updateSleepCycle(GameObject* obj, NwMammothState* state) {
    u8 night;
    int animCue;
    f32 sunTime;
    PartFxSpawnParams partfxBlock;

    night = (u8)(*gSkyInterface)->getSunPosition(&sunTime);
    if (state->animEvents.triggerCount != 0) {
        animCue = state->animEvents.triggeredIds[0] == 0;
    } else {
        animCue = 0;
    }
    if (state->stateIndex < NW_MAMMOTH_STATE_SLEEP_START) {
        if (night != 0) {
            if (state->pathSpeed > 0.0f) {
                return -1;
            }
            state->daytimeStateIndex = state->stateIndex;
            state->stateIndex = NW_MAMMOTH_STATE_SLEEP_START;
        } else {
            return 0;
        }
    }
    switch (state->stateIndex) {
    case NW_MAMMOTH_STATE_SLEEP_START:
        if (animCue != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_id_14b);
        }
        if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_ANIM_ENDED) {
            state->stateIndex = NW_MAMMOTH_STATE_SLEEPING;
            state->stateTimer = (f32)(s32)randomGetRange(0, 300);
        }
        break;
    case NW_MAMMOTH_STATE_SLEEPING:
        if (animCue != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_sa_off);
        }
        state->stateTimer -= timeDelta;
        if (night == 0 && state->stateTimer <= 0.0f) {
            state->stateIndex = NW_MAMMOTH_STATE_WAKE_UP;
        }
        {
            f32 t = state->partfxTimer - timeDelta;
            state->partfxTimer = t;
            if (t <= 0.0f) {
                if (obj->objectFlags & OBJECT_OBJFLAG_RENDERED) {
                    partfxBlock.posX = state->spawnPosX;
                    partfxBlock.posY = state->spawnPosY;
                    partfxBlock.posZ = state->spawnPosZ;
                    (*gPartfxInterface)->spawnObject(obj, NW_MAMMOTH_PARTFX, &partfxBlock, 0x200001, -1, NULL);
                }
                state->partfxTimer = 30.0f;
            }
        }
        break;
    case NW_MAMMOTH_STATE_WAKE_UP:
        if (animCue != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_id_14d);
        }
        if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_ANIM_ENDED) {
            state->stateIndex = state->daytimeStateIndex;
        }
        break;
    }
    return 1;
}

void NW_mammoth_updateGatekeeper(GameObject* obj, NwMammothState* state, NwMammothPlacement* placement) {
    GameObject* tw2;
    GameObject* tw;
    GameObject* nearestObj = objGetNearestTypeTo(NW_MAMMOTH_TARGET_OBJECT_GROUP, obj, 0);

    switch (state->stateIndex) {
    case NW_MAMMOTH_STATE_GATEKEEPER_IDLE:
        state->sfxTimer += timeDelta;
        if (state->sfxTimer > 900.0f) {
            Sfx_PlayFromObject(obj, SFXTRIG_skeep_mumb);
            state->sfxTimer -= 900.0f;
        }
        if (state->playerDistanceSq < (f32)(s32)(placement->triggerDistance * placement->triggerDistance)) {
            state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_ALERT;
        }
        break;
    case NW_MAMMOTH_STATE_GATEKEEPER_ALERT:
        if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_ANIM_ENDED) {
            state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_PROMPT;
        }
        break;
    case NW_MAMMOTH_STATE_GATEKEEPER_PROMPT:
        state->sfxTimer += timeDelta;
        if (state->sfxTimer > 900.0f) {
            Sfx_PlayFromObject(obj, SFXTRIG_skeep_mumb);
            state->sfxTimer -= 900.0f;
        }
        if (ObjTrigger_IsSet(obj) != 0) {
            (*gObjectTriggerInterface)->runSequence(3, (void*)nearestObj, -1);
            state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK;
            state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_COLLECTING;
            mainSetBits(GAMEBIT_NW_ReturnedTo, 1);
            mainSetBits(GAMEBIT_NW_GateKeeperAirMeterActive, 1);
        }
        break;
    case NW_MAMMOTH_STATE_GATEKEEPER_RESUME_RESCUE:
        (*gObjectTriggerInterface)->preempt((int)nearestObj, 0x5aa);
        (*gObjectTriggerInterface)->runSequence(3, (void*)nearestObj, 0x30);
        state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_COLLECTING;
        break;
    case NW_MAMMOTH_STATE_GATEKEEPER_COLLECTING: {
        int n = 4;
        if (mainGetBit(0x120) == 0) {
            n = 3;
        }
        if (mainGetBit(0x121) == 0) {
            n -= 1;
        }
        {
            int i = 0;
            for (; i < n; i++) {
                if (mainGetBit(gNwMammothRescueBushClearedGameBits[i]) != 0) {
                    mainSetBits(gNwMammothRescueBushClearedGameBits[i], 0);
                }
                {
                    int* o2 = (int*)ObjList_FindObjectById(gNwMammothRescueBushObjectIds[i]);
                    if ((int*)playerGetTargetObject((GameObject*)state->playerObject) == o2) {
                        enemy_setTrackedObj((GameObject*)o2, state->playerObject);
                    } else {
                        tw = tumbleweedbush_findNearestActive(&((GameObject*)o2)->anim.worldPosX);
                        if (tw == NULL || vec3f_distanceSquared(&tw->anim.worldPosX, (f32*)&o2[6]) >= 250000.0f) {
                            if (vec3f_distanceSquared(&((GameObject*)state->playerObject)->anim.worldPosX,
                                                      (f32*)&o2[6]) >= 250000.0f) {
                                enemy_setTrackedObj((GameObject*)o2, obj);
                            } else {
                                enemy_setTrackedObj((GameObject*)o2, state->playerObject);
                            }
                        } else {
                            enemy_setTrackedObj((GameObject*)o2, tw);
                        }
                    }
                }
            }
        }
        {
            tw2 = tumbleweedbush_findNearestActive(&state->spawnPosX);
            if (tw2 != NULL) {
                GameObject* tk = getTrickyObject();
                TRICKY_INTERFACE(tk)->sideCommandEnable(tk, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                                        TRICKY_COMMAND_TYPE_FIND_SECRET);
            }
            state->triggerList = gNwMammothGatekeeperCollectionTriggerList;
            if (state->trackedObject == NULL) {
                NwMammothPlacement* setup = (NwMammothPlacement*)obj->anim.placementData;
                if (tw2 != NULL && tw2->anim.romDefNo == TUMBLEWEED_BUSH_SIBLING_B) {
                    if (getXZDistanceSquared(&obj->anim.worldPosX, &tw2->anim.worldPosX) <
                        (f32)(s32)(setup->triggerDistance * setup->triggerDistance)) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                            Sfx_PlayFromObject(obj, SFXTRIG_mammoth_snowstep);
                        }
                        if ((*(NwMammothTumbleweedInterface**)tw2->anim.dll)->isHoming(tw2) == 0) {
                            (*(NwMammothTumbleweedInterface**)tw2->anim.dll)->startHoming(tw2, &state->spawnPosX);
                            state->trackedObject = tw2;
                            state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_HOMING_TUMBLEWEED;
                        }
                    }
                }
            }
        }
        if (!(state->runtimeFlags & NW_MAMMOTH_RUNTIME_UI_MESSAGE)) {
            (*gGameUIInterface)->initAirMeter(NW_MAMMOTH_AIR_METER_MAX_VALUE, NW_MAMMOTH_AIR_METER_BG_TEXTURE);
            state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_UI_MESSAGE;
        }
        break;
    }
    case NW_MAMMOTH_STATE_GATEKEEPER_HOMING_TUMBLEWEED:
        if (getXZDistanceSquared(&state->spawnPosX, &state->trackedObject->anim.worldPosX) < 6.25f) {
            Sfx_PlayFromObject(obj, SFXTRIG_mammoth_annoyed);
            tumbleweedbush_activatePiece(state->trackedObject);
            state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_BREAK_TUMBLEWEED;
        }
        break;
    case NW_MAMMOTH_STATE_GATEKEEPER_BREAK_TUMBLEWEED:
        if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_ANIM_ENDED) {
            Obj_FreeObject(state->trackedObject);
            state->trackedObject = NULL;
            if (++state->uiMessageCount > 3) {
                state->uiMessageCount = 3;
            }
            mainSetBits(GAMEBIT_NW_MammothTumbleweedCount, state->uiMessageCount);
            if (state->uiMessageCount >= 3) {
                state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_RESCUE_COMPLETE;
            } else {
                if (state->uiMessageCount % 2 == 0) {
                    Sfx_PlayFromObject(obj, SFXTRIG_id_14f);
                }
                state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_COLLECTING;
            }
        }
        break;
    case NW_MAMMOTH_STATE_GATEKEEPER_RESCUED_SEQUENCE:
        (*gObjectTriggerInterface)->preempt((int)nearestObj, 0x157c);
        (*gObjectTriggerInterface)->runSequence(1, (void*)nearestObj, 2);
        state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_POST_RESCUE;
        break;
    case NW_MAMMOTH_STATE_GATEKEEPER_RESCUE_COMPLETE:
        if (!(state->playerObject->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) &&
            state->airMeterValue >= NW_MAMMOTH_AIR_METER_MAX_VALUE) {
            Sfx_PlayFromObject(obj, SFXTRIG_menuups16k);
            (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_BLACK);
            state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_TRANSITION;
            mainSetBits(GAMEBIT_NW_GateKeeperAirMeterActive, 0);
            state->runtimeFlags = state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_UI_MESSAGE;
            (*gGameUIInterface)->airMeterSetShutdown();
        }
        break;
    case NW_MAMMOTH_STATE_GATEKEEPER_TRANSITION:
        if (!(state->playerObject->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK)) {
            if ((*gScreenTransitionInterface)->isFinished() != 0) {
                mainSetBits(GAMEBIT_NW_RescuedSnowHornGateKeeper, 1);
                (*gObjectTriggerInterface)->runSequence(1, (void*)nearestObj, -1);
                state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_POST_RESCUE;
            }
        }
        break;
    case NW_MAMMOTH_STATE_GATEKEEPER_POST_RESCUE:
    default:
        if (mainGetBit(0x224) != 0) {
            state->triggerList = gNwMammothGatekeeperBit224TriggerList;
        } else {
            if (mainGetBit(GAMEBIT_NW_GateKeeperCommsPlayed) == 0) {
                mainSetBits(GAMEBIT_NW_GateKeeperCommsPlayed, 1);
                mainSetBits(GAMEBIT_IncomingCommunication, 1);
            }
            state->triggerList = gNwMammothGatekeeperDefaultTriggerList;
        }
        NW_mammoth_updateSleepCycle(obj, state);
        break;
    }
    if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_UI_MESSAGE) {
        if (state->airMeterValue < 66.666664f * state->uiMessageCount) {
            state->airMeterValue += timeDelta;
        }
        if (state->airMeterValue >= NW_MAMMOTH_AIR_METER_MAX_VALUE) {
            (*gGameUIInterface)->runAirMeter(NW_MAMMOTH_AIR_METER_MAX_VALUE);
        } else {
            (*gGameUIInterface)->runAirMeter((int)state->airMeterValue);
        }
    }
}

void NW_mammoth_updatePatrol(GameObject* obj, NwMammothState* state, NwMammothPlacement* placement) {
    switch (NW_mammoth_updateSleepCycle(obj, state)) {
    case -1:
        state->pathSpeed -= 0.01f * timeDelta;
        if (state->pathSpeed < 0.05f) {
            state->pathSpeed = 0.0f;
        }
        break;
    case 0:
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) || state->playerDistanceSq < 6400.0f) {
            state->pathSpeed -= 0.02f * timeDelta;
            if (state->pathSpeed < 0.05f) {
                state->pathSpeed = 0.0f;
            }
        } else {
            state->pathSpeed += 0.01f * timeDelta;
            if (state->pathSpeed > 0.5f) {
                state->pathSpeed = 0.5f;
            }
        }
        break;
    case 1:
        return;
    }
    switch (state->stateIndex) {
    case NW_MAMMOTH_STATE_PATROL_MOVING: {
        Curve* curve = &state->curveState.curve;
        if (Curve_AdvanceAlongPath(curve, state->pathSpeed) != 0 || curve->idx != 0) {
            (*gRomCurveInterface)->goNextPoint(curve);
        }
        {
            f32 dx = curve->sample[0] - obj->anim.localPosX;
            f32 dz = curve->sample[2] - obj->anim.localPosZ;
            ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj, oneOverTimeDelta * sqrtf(dx * dx + dz * dz),
                                         &state->animStepScale);
        }
        obj->anim.rotX = (s16)(getAngle(curve->tangent[0], curve->tangent[2]) + 0x8000);
        obj->anim.localPosX = curve->sample[0];
        obj->anim.localPosZ = curve->sample[2];
        if (state->pathSpeed <= 0.0f) {
            state->stateIndex = NW_MAMMOTH_STATE_PATROL_PAUSED;
        }
        break;
    }
    case NW_MAMMOTH_STATE_PATROL_PAUSED:
        if (state->pathSpeed > 0.1f) {
            state->stateIndex = NW_MAMMOTH_STATE_PATROL_MOVING;
        }
        break;
    }
    if (placement->behaviorMode == NW_MAMMOTH_BEHAVIOR_MODE1_PATROL) {
        if (mainGetBit(GAMEBIT_SnowHornArtifact19D) != 0) {
            state->triggerList = gNwMammothMode1ArtifactCompleteTriggerList;
        } else if (mainGetBit(GAMEBIT_ITEM_NWSnowHornArtifact_Got) != 0) {
            state->triggerList = gNwMammothMode1ArtifactObtainedTriggerList;
        } else if (mainGetBit(GAMEBIT_NW_RescuedSnowHornGateKeeper) != 0) {
            state->triggerList = gNwMammothMode1RescuedTriggerList;
        } else if (mainGetBit(GAMEBIT_Tricky_Learned_Distract) != 0) {
            state->triggerList = gNwMammothMode1TrickyDistractTriggerList;
        } else {
            state->triggerList = gNwMammothMode1DefaultTriggerList;
        }
    } else if (mainGetBit(GAMEBIT_SnowHornArtifact19D) != 0) {
        state->triggerList = gNwMammothPatrolArtifactCompleteTriggerList;
    } else if (mainGetBit(GAMEBIT_ITEM_NWSnowHornArtifact_Got) != 0) {
        state->triggerList = gNwMammothPatrolArtifactObtainedTriggerList;
    } else if (mainGetBit(GAMEBIT_NW_RescuedSnowHornGateKeeper) != 0) {
        state->triggerList = gNwMammothPatrolRescuedTriggerList;
    } else if (mainGetBit(GAMEBIT_Tricky_Learned_Distract) != 0) {
        state->triggerList = gNwMammothPatrolTrickyDistractTriggerList;
    } else {
        state->triggerList = gNwMammothPatrolDefaultTriggerList;
    }
}

void NW_mammoth_updateArtifactQuest(GameObject* obj, NwMammothState* state, NwMammothPlacement* placement) {
    (void)placement;
    switch (state->stateIndex) {
    case NW_MAMMOTH_STATE_ARTIFACT_PROMPT:
        state->triggerList = gNwMammothArtifactPromptTriggerList;
        if (ObjTrigger_IsSetById(obj, 418) != 0) {
            state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK;
            mainSetBits(GAMEBIT_SnowHornArtifact19D, 1);
            mainSetBits(GAMEBIT_ITEM_NWSnowHornArtifact_Used, 1);
            mainSetBits(GAMEBIT_ITEM_SnowHornArtifactEE5, 1);
            mainSetBits(GAMEBIT_ITEM_SnowHornArtifactEE6, 1);
            state->stateIndex = NW_MAMMOTH_STATE_ARTIFACT_COLLECTED;
        }
        break;
    case NW_MAMMOTH_STATE_ARTIFACT_COLLECTED:
        state->triggerList = gNwMammothArtifactCollectedTriggerList;
        if (mainGetBit(GAMEBIT_SnowHornArtifact19F) != 0) {
            state->stateIndex = NW_MAMMOTH_STATE_ARTIFACT_COMPLETE;
        }
        break;
    case NW_MAMMOTH_STATE_ARTIFACT_COMPLETE:
        state->triggerList = gNwMammothArtifactCompleteTriggerList;
        break;
    }
}

void NW_mammoth_updateFeedQuest(GameObject* obj, NwMammothState* state, NwMammothPlacement* placement) {
    (void)placement;
    if (NW_mammoth_updateSleepCycle(obj, state) != 0) {
        return;
    }

    switch (state->stateIndex) {
    case NW_MAMMOTH_STATE_FEED_INTRO:
        state->triggerList = gNwMammothFeedIntroTriggerList;
        if (mainGetBit(211) != 0) {
            state->stateIndex = NW_MAMMOTH_STATE_FEED_FIRST_ROOT;
        }
        break;
    case NW_MAMMOTH_STATE_FEED_FIRST_ROOT:
        state->triggerList = gNwMammothFeedFirstRootTriggerList;
        switch (mainGetBit(GAMEBIT_ITEM_AlpineRoot_Used)) {
        case 0:
            if (ObjTrigger_IsSetById(obj, 1398) != 0) {
                mainSetBits(GAMEBIT_ITEM_AlpineRoot_Used, 1);
                gameBitDecrement(GAMEBIT_ITEM_IMAlpineRoot_Count);
                (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK;
                state->stateIndex = NW_MAMMOTH_STATE_FEED_SECOND_ROOT;
            }
            break;
        case 1:
            state->stateIndex = NW_MAMMOTH_STATE_FEED_SECOND_ROOT;
            break;
        default:
            state->stateIndex = NW_MAMMOTH_STATE_FEED_SATISFIED;
            break;
        }
        break;
    case NW_MAMMOTH_STATE_FEED_SECOND_ROOT:
        state->triggerList = gNwMammothFeedSecondRootTriggerList;
        if (ObjTrigger_IsSetById(obj, 1398) != 0) {
            mainSetBits(GAMEBIT_ITEM_AlpineRoot_Used, 2);
            gameBitDecrement(GAMEBIT_ITEM_IMAlpineRoot_Count);
            (*gObjectTriggerInterface)->runSequence(4, obj, -1);
            state->stateIndex = NW_MAMMOTH_STATE_FEED_SATISFIED;
            state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK;
        }
        break;
    case NW_MAMMOTH_STATE_FEED_SATISFIED:
        state->triggerList = gNwMammothFeedSatisfiedTriggerList;
        break;
    }
}

int NW_mammoth_getExtraSize(void) {
    return sizeof(NwMammothState);
}

void NW_mammoth_free(GameObject* obj) {
    NwMammothState* state;

    state = (NwMammothState*)obj->extra;
    objFreeObjectType(obj, NW_MAMMOTH_GROUP_ID);
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_UI_MESSAGE) != 0) {
        (*gGameUIInterface)->airMeterSetShutdown();
    }
}

void NW_mammoth_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char unusedVisible) {
    int i;
    NwMammothState* state;

    (void)unusedVisible;
    state = (NwMammothState*)obj->extra;
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    for (i = 0; i < NW_MAMMOTH_PATH_POINT_COUNT; i++) {
        ObjPath_GetPointWorldPosition(obj, i, &state->pathPoints[i].x, &state->pathPoints[i].y, &state->pathPoints[i].z,
                                      0);
    }
    ObjPath_GetPointWorldPosition(obj, NW_MAMMOTH_PATH_POINT_COUNT, &state->spawnPosX, &state->spawnPosY,
                                  &state->spawnPosZ, 0);
}

void NW_mammoth_update(GameObject* obj, int unusedArg) {
    int triggerIndex;
    f32 stepScale;
    int currentMove;
    ObjHitReactEntry* hitReactEntries;
    u8 stateFlags;
    u8 stateIndex;
    NwMammothTables* tables[1];
    NwMammothState* state;
    NwMammothPlacement* placement;

    (void)unusedArg;
    tables[0] = (NwMammothTables*)gNwMammothHitReactEntriesData;
    state = (NwMammothState*)obj->extra;
    placement = (NwMammothPlacement*)obj->anim.placementData;
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_RESET_PATH) != 0) {
        state->runtimeFlags = state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_RESET_PATH;
    }
    state->playerObject = Obj_GetPlayerObject();
    if (state->playerObject == NULL) {
        return;
    }
    stateIndex = state->stateIndex;
    stateFlags = tables[0]->stateFlags[stateIndex];
    if ((stateFlags & NW_MAMMOTH_STATE_FLAG_SOLID) != 0) {
        obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_SHADOW_DISABLED);
        obj->anim.modelState->flags = obj->anim.modelState->flags & ~(u64)OBJ_MODEL_STATE_SHADOW_VISIBLE;
    } else {
        obj->objectFlags = (u16)(obj->objectFlags & ~OBJECT_OBJFLAG_SHADOW_DISABLED);
        obj->anim.modelState->flags = obj->anim.modelState->flags | OBJ_MODEL_STATE_SHADOW_VISIBLE;
    }
    stateFlags = tables[0]->stateFlags[state->stateIndex];
    if ((stateFlags & NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT) == 0) {
        if ((stateFlags & NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT) != 0) {
            hitReactEntries = &tables[0]->heavyHitReactEntry;
        } else {
            hitReactEntries = &tables[0]->normalHitReactEntry;
        }
        state->hitReactState =
            ObjHitReact_Update(obj, hitReactEntries, 1, state->hitReactState, &state->hitReactStepScale);
        if (state->hitReactState != 0) {
            characterHeadLookRelax(obj, &state->eyeAnim);
            characterDoEyeAnims(obj, &state->eyeAnim);
            return;
        }
    }
    state->playerDistanceSq = vec3f_distanceSquared(&obj->anim.worldPosX, &state->playerObject->anim.worldPosX);
    switch (placement->behaviorMode) {
    case NW_MAMMOTH_BEHAVIOR_FEED_QUEST:
        NW_mammoth_updateFeedQuest(obj, state, placement);
        break;
    case NW_MAMMOTH_BEHAVIOR_ARTIFACT_QUEST:
        NW_mammoth_updateArtifactQuest(obj, state, placement);
        break;
    case NW_MAMMOTH_BEHAVIOR_MODE1_PATROL:
    case NW_MAMMOTH_BEHAVIOR_PATROL:
        NW_mammoth_updatePatrol(obj, state, placement);
        break;
    case NW_MAMMOTH_BEHAVIOR_GATEKEEPER:
        NW_mammoth_updateGatekeeper(obj, state, placement);
        break;
    }
    if ((tables[0]->stateFlags[state->stateIndex] & NW_MAMMOTH_STATE_FLAG_PATH_CONTROL) != 0) {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        if (((tables[0]->stateFlags[state->stateIndex] & NW_MAMMOTH_STATE_FLAG_MENU_ACTION) != 0) &&
            (cMenuGetSelectedItem() != -1)) {
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 4);
        } else {
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
        }
    }
    stateIndex = state->stateIndex;
    if (obj->anim.currentMove != (currentMove = tables[0]->stateMoveIds[stateIndex])) {
        stepScale = tables[0]->stateMoveStepScales[stateIndex];
        if (stepScale > 0.0f) {
            ObjAnim_SetCurrentMove(obj, currentMove, 0.0f, 0);
        } else {
            ObjAnim_SetCurrentMove(obj, currentMove, 1.0f, 0);
        }
        state->animStepScale = tables[0]->stateMoveStepScales[state->stateIndex];
    }
    if (ObjAnim_AdvanceCurrentMove(obj, state->animStepScale, timeDelta, &state->animEvents) != 0) {
        state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_ANIM_ENDED;
    } else {
        state->runtimeFlags = state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_ANIM_ENDED;
    }
    objAudioDispatchAnimEvents(obj, &state->animEvents, 8, state->pathPoints, &state->pathState, 1.0f, 1.0f);
    NW_mammoth_updateEyeTracking(obj, state,
                                 tables[0]->stateFlags[state->stateIndex] & NW_MAMMOTH_STATE_FLAG_TRIGGER_REFRESH);
    state->runtimeFlags = state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH;
    if (((state->runtimeFlags & NW_MAMMOTH_RUNTIME_MENU_LOCK) == 0) && (ObjTrigger_IsSet(obj) != 0)) {
        triggerIndex = randomGetRange(NW_MAMMOTH_TRIGGER_RANDOM_MIN, *state->triggerList);
        state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH;
        (*gObjectTriggerInterface)->runSequence(state->triggerList[triggerIndex], obj, -1);
    }
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_PATH_CONTROL) != 0) {
        (*gPathControlInterface)->update(obj, &state->pathState, timeDelta);
        (*gPathControlInterface)->apply(obj, &state->pathState);
        (*gPathControlInterface)->advance(obj, &state->pathState, timeDelta);
    }
}

void NW_mammoth_init(GameObject* obj, NwMammothPlacement* placement, int isReload) {
    extern const f32 gNwMammothDefaultAnimStepScale;
    NwMammothState* state = (NwMammothState*)obj->extra;
    NwMammothPathParams pathParam = sNwMammothPathParams;
    int curveParam;

    obj->anim.rotX = (s16)(placement->modelIndex << 8);
    obj->animEventCallback = NW_mammoth_processAnimEvents;
    if (isReload != 0) {
        return;
    }
    state->animStepScale = gNwMammothDefaultAnimStepScale;
    switch (placement->behaviorMode) {
    case NW_MAMMOTH_BEHAVIOR_FEED_QUEST:
        state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_PATH_CONTROL;
        break;
    case NW_MAMMOTH_BEHAVIOR_ARTIFACT_QUEST:
        state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_PATH_CONTROL;
        if (mainGetBit(GAMEBIT_SnowHornArtifact19F) != 0) {
            state->stateIndex = NW_MAMMOTH_STATE_ARTIFACT_COMPLETE;
        } else if (mainGetBit(GAMEBIT_SnowHornArtifact19D) != 0) {
            state->stateIndex = NW_MAMMOTH_STATE_ARTIFACT_COLLECTED;
        } else {
            state->stateIndex = NW_MAMMOTH_STATE_ARTIFACT_PROMPT;
        }
        break;
    case NW_MAMMOTH_BEHAVIOR_MODE1_PATROL:
    case NW_MAMMOTH_BEHAVIOR_PATROL:
        curveParam = NW_MAMMOTH_CURVE_PARAM;
        state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_PATH_CONTROL;
        if ((u8)(*gRomCurveInterface)->initCurve(&state->curveState.curve, obj, 1000.0f, &curveParam, -1) == 0) {
            obj->anim.localPosX = state->curveState.curve.sample[0];
            obj->anim.localPosZ = state->curveState.curve.sample[2];
            state->stateIndex = NW_MAMMOTH_STATE_PATROL_MOVING;
            state->pathSpeed = 0.5f;
        }
        break;
    case NW_MAMMOTH_BEHAVIOR_GATEKEEPER:
        state->uiMessageCount = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        if (mainGetBit(GAMEBIT_NW_RescuedSnowHornGateKeeper) != 0) {
            state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_RESCUED_SEQUENCE;
        } else if (mainGetBit(GAMEBIT_NW_ReturnedTo) != 0) {
            state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_RESUME_RESCUE;
            if (state->uiMessageCount >= 3) {
                (*gGameUIInterface)->initAirMeter(NW_MAMMOTH_AIR_METER_MAX_VALUE, NW_MAMMOTH_AIR_METER_BG_TEXTURE);
                state->runtimeFlags = state->runtimeFlags | NW_MAMMOTH_RUNTIME_UI_MESSAGE;
                state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_RESCUE_COMPLETE;
            }
        } else {
            state->stateIndex = NW_MAMMOTH_STATE_GATEKEEPER_IDLE;
        }
        break;
    }
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_PATH_CONTROL) != 0) {
        CurvesCollisionState* path = &state->pathState;
        (*gPathControlInterface)->init(path, 3, 2, 1);
        (*gPathControlInterface)
            ->setup(path, NW_MAMMOTH_PATH_SETUP_POINT_COUNT, gNwMammothPathSetupDataA, gNwMammothPathSetupDataB,
                    pathParam.values);
        (*gPathControlInterface)->attachObject(obj, path);
    }
    objAddObjectType(obj, NW_MAMMOTH_GROUP_ID);
}

const f32 gNwMammothDefaultAnimStepScale = 0.005f;
