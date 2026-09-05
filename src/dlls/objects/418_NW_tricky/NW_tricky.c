/*
 * NW_tricky (DLL 0x1A2) - SnowHorn Wastes controller for Tricky.
 *
 * The SnowHorn tutorial first keeps the matching SharpClaw actors chasing
 * whichever of the player or Tricky is nearer and offers live configured
 * targets to Tricky's play-ball command. The follow-up sidekick-command
 * learning phase synchronizes Tricky's talk state with the map-event energy
 * gauge.
 */
#include "dlls/objects/418_NW_tricky.h"

#include "main/audio/sfx_ids.h"
#include "main/dll/dll_00C4_tricky.h"
#include "dlls/objects/201_Baddie.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/dll/dll_80136a40.h"
#include "main/objtype.h"

#define NW_TRICKY_SHARPCLAW_OBJECT_GROUP 3
#define NW_TRICKY_SHARPCLAW_SEQUENCE_ID  0x13A

#define NW_TRICKY_SOUND_CHANNEL                 16
#define NW_TRICKY_MOUTH_OPEN_ANGLE              0x1000
#define NW_TRICKY_CALL_FOR_HELP_INTERVAL_FRAMES 600.0f

#define NW_TRICKY_PLAY_BALL_COMMAND_ENABLED 1
#define NW_TRICKY_MINIMUM_TARGET_HEALTH     0.0f

#define NW_TRICKY_MINIMUM_ENERGY             4
#define NW_TRICKY_ENERGY_LOW_GAMEBIT_VALUE   1
#define NW_TRICKY_ENERGY_READY_GAMEBIT_VALUE 0xFF
#define NW_TRICKY_ENERGY_UPDATE_INTERVAL     2000.0f

typedef struct NwTrickyPlayBallTargetIdList {
    int ids[NW_TRICKY_PLAY_BALL_TARGET_ID_COUNT];
} NwTrickyPlayBallTargetIdList;

STATIC_ASSERT(sizeof(NwTrickyPlayBallTargetIdList) == 0x0C);

const int gNwTrickyPlayBallTargetIds[NW_TRICKY_PLAY_BALL_TARGET_POOL_SIZE] = {0xF5B, 0x43EC9, 0x43ED6, 0};

int nwTricky_processAnimEvents(GameObject* unusedObj, int unusedArg, ObjSeqState* unusedAnimUpdate) {
    (void)unusedObj;
    (void)unusedArg;
    (void)unusedAnimUpdate;

    Sfx_StopObjectChannel(getTrickyObject(), NW_TRICKY_SOUND_CHANNEL);
    return 0;
}

int nwTricky_getExtraSize(void) {
    return sizeof(NwTrickyState);
}

void nwTricky_free(GameObject* unusedObj) {
    (void)unusedObj;

    mainSetBits(GAMEBIT_Tricky_Unlocked_Sidekick_Commands, 1);
}

void nwTricky_update(GameObject* obj) {
    int herdObjectCount;
    NwTrickyPlayBallTargetIdList targetIds;
    NwTrickyState* state;
    GameObject* tricky;
    GameObject* player;
    GameObject** herdObjects;
    int targetIndex;
    GameObject* target;
    f32 playerDistanceSquared;
    f32 phaseTimer;
    f32 minimumHealth;
    int herdObjectIndex;

    state = obj->extra;
    tricky = getTrickyObject();
    player = Obj_GetPlayerObject();
    targetIds = *(NwTrickyPlayBallTargetIdList*)gNwTrickyPlayBallTargetIds;

    if (tricky == NULL) {
        return;
    }

    switch (state->phase) {
    case NW_TRICKY_PHASE_CHASED_BY_SHARPCLAW:
        if (mainGetBit(GAMEBIT_NW_TrickySharpClawDefeated)) {
            herdObjects = (GameObject**)objGetAllOfType(NW_TRICKY_SHARPCLAW_OBJECT_GROUP, &herdObjectCount);
            for (herdObjectIndex = 0; herdObjectIndex < herdObjectCount; herdObjectIndex++) {
                if (herdObjects[herdObjectIndex]->anim.romDefNo == NW_TRICKY_SHARPCLAW_SEQUENCE_ID) {
                    enemy_setTrackedObj(herdObjects[herdObjectIndex], player);
                }
            }
            mainSetBits(GAMEBIT_Tricky_Unlocked_Sidekick_Commands, 1);
            state->phase = NW_TRICKY_PHASE_LEARNING_COMMANDS;
        } else {
            if (mainGetBit(GAMEBIT_ITEM_TrickyStayFind_Got)) {
                if (TRICKY_INTERFACE(tricky)->isPlayingBall(tricky) == 0) {
                    mainSetBits(GAMEBIT_Tricky_Unlocked_Sidekick_Commands, 0);
                    state->phaseTimer = 0.0f;
                }

                for (targetIndex = 0, minimumHealth = NW_TRICKY_MINIMUM_TARGET_HEALTH;
                     targetIndex < NW_TRICKY_PLAY_BALL_TARGET_ID_COUNT; targetIndex++) {
                    target = ObjList_FindObjectById(targetIds.ids[targetIndex]);
                    if (target != NULL && enemy_getHealthFraction(target) > minimumHealth) {
                        TRICKY_INTERFACE(tricky)->commandPlayBall(tricky, NW_TRICKY_PLAY_BALL_COMMAND_ENABLED, target);
                        break;
                    }
                }

                state->phaseTimer += timeDelta;
                phaseTimer = state->phaseTimer;
                if (phaseTimer >= NW_TRICKY_CALL_FOR_HELP_INTERVAL_FRAMES) {
                    state->phaseTimer = phaseTimer - NW_TRICKY_CALL_FOR_HELP_INTERVAL_FRAMES;
                    trickyTryPlaySound(tricky, SFXwp_rolovr_6, NW_TRICKY_MOUTH_OPEN_ANGLE);
                }
            }

            herdObjects = (GameObject**)objGetAllOfType(NW_TRICKY_SHARPCLAW_OBJECT_GROUP, &herdObjectCount);
            for (herdObjectIndex = 0; herdObjectIndex < herdObjectCount; herdObjectIndex++) {
                if (herdObjects[herdObjectIndex]->anim.romDefNo == NW_TRICKY_SHARPCLAW_SEQUENCE_ID) {
                    playerDistanceSquared =
                        vec3f_distanceSquared(&herdObjects[herdObjectIndex]->anim.worldPosX, &player->anim.worldPosX);
                    if (vec3f_distanceSquared(&herdObjects[herdObjectIndex]->anim.worldPosX, &tricky->anim.worldPosX) <
                        playerDistanceSquared) {
                        enemy_setTrackedObj(herdObjects[herdObjectIndex], tricky);
                    } else {
                        enemy_setTrackedObj(herdObjects[herdObjectIndex], player);
                    }
                }
            }
        }
        break;
    case NW_TRICKY_PHASE_LEARNING_COMMANDS:
        if (!(tricky->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK)) {
            state->phaseTimer += timeDelta;
        }
        if (mainGetBit(GAMEBIT_TrickyTalk) == NW_TRICKY_ENERGY_LOW_GAMEBIT_VALUE) {
            if ((*gMapEventInterface)->getTrickyStats()->energy >= NW_TRICKY_MINIMUM_ENERGY) {
                mainSetBits(GAMEBIT_TrickyTalk, NW_TRICKY_ENERGY_READY_GAMEBIT_VALUE);
            }
        }
        phaseTimer = state->phaseTimer;
        if (phaseTimer >= NW_TRICKY_ENERGY_UPDATE_INTERVAL) {
            state->phaseTimer = phaseTimer - NW_TRICKY_ENERGY_UPDATE_INTERVAL;
            if (mainGetBit(GAMEBIT_TrickyTalk) == NW_TRICKY_ENERGY_READY_GAMEBIT_VALUE) {
                if ((*gMapEventInterface)->getTrickyStats()->energy < NW_TRICKY_MINIMUM_ENERGY) {
                    mainSetBits(GAMEBIT_TrickyTalk, NW_TRICKY_ENERGY_LOW_GAMEBIT_VALUE);
                }
            }
        }
        break;
    }
}

void nwTricky_init(GameObject* obj) {
    obj->animEventCallback = nwTricky_processAnimEvents;
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
}

ObjectDescriptor gNWTrickyObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)nwTricky_init,
    (ObjectDescriptorCallback)nwTricky_update,
    0,
    0,
    (ObjectDescriptorCallback)nwTricky_free,
    0,
    nwTricky_getExtraSize,
};
