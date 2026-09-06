/*
 * NW_levcontr (DLL 0x1A5) - the SnowHorn Wastes level controller (map
 * 'nwastes', 0x0A).
 *
 * Runs the area's overall progression: a countdown that gates a hint
 * message, the day/night music swap driven by the sun position, a set of
 * latched game-bit reactions, the timed-challenge timer, and a state machine
 * that walks a table of target objects and fires their trigger sequences.
 */
#include "dlls/objects/421_NW_levcontr.h"

#include "dlls/objects/416_NW_geyser.h"
#include "game/objects/object.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "main/dll/savegame_load_api.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/gametext_show_api.h"
#include "main/mapEventTypes.h"
#include "main/model_engine.h"
#include "main/obj_trigger.h"
#include "main/objseq.h"
#include "main/render_envfx_api.h"
#include "main/sky.h"
#include "main/sky_interface.h"
#include "sys/objects.h"
#include "main/game_timer_control_api.h"
#include "main/sky_api.h"

#define NW_LEVEL_CONTROL_HINT_TEXT_ID       0x435
#define NW_LEVEL_CONTROL_HINT_DURATION      300.0f
#define NW_LEVEL_CONTROL_ENVIRONMENT_EFFECT 0x23C
#define NW_LEVEL_CONTROL_DAY_NIGHT_MUSIC_ID 0x1A
#define NW_LEVEL_CONTROL_TIMER_END_MUSIC_ID 0xAF
#define NW_LEVEL_CONTROL_TRIGGER_ID         0x1EE
#define NW_LEVEL_CONTROL_TIMER_ID           0x15
#define NW_LEVEL_CONTROL_SECONDS_PER_MINUTE 60.0f

#define NW_LEVEL_CONTROL_FLAG_TIMER_START_PENDING 0x01
#define NW_LEVEL_CONTROL_FLAG_TIMER_RUNNING       0x02
#define NW_LEVEL_CONTROL_FLAG_TIMER_COMPLETE      0x04
#define NW_LEVEL_CONTROL_FLAG_DAY_NIGHT_MUSIC     0x10

STATIC_ASSERT(sizeof(NwLevelControlData) == NW_LEVEL_CONTROL_DATA_SIZE);
STATIC_ASSERT(offsetof(NwLevelControlData, targetObjectIds) == 0x00);
STATIC_ASSERT(offsetof(NwLevelControlData, sequenceIds) == 0x1C);
STATIC_ASSERT(offsetof(NwLevelControlData, nextModes) == 0x38);
STATIC_ASSERT(offsetof(NwLevelControlData, skyRampA) == 0x54);
STATIC_ASSERT(offsetof(NwLevelControlData, skyRampB) == 0x8C);
STATIC_ASSERT(offsetof(NwLevelControlData, skyRampC) == 0xC4);
STATIC_ASSERT(offsetof(NwLevelControlData, skyRampD) == 0xFC);

NwLevelControlData gNwLevelControlData = {
    {280533, 280534, 280533, 280534, 280533, 280534, 280533},
    {2, 3, 4, 5, 6, 7, 1},
    {3, 4, 5, 6, 7, 8, 11},
    {
        180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180,
        180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180,
    },
    {
        182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182,
        182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182,
    },
    {
        181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181,
        181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181,
    },
    {
        183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183,
        183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183,
    },
};

ObjectDescriptor gNWLevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)nwLevelControl_init,
    (ObjectDescriptorCallback)nwLevelControl_update,
    0,
    0,
    (ObjectDescriptorCallback)nwLevelControl_free,
    0,
    nwLevelControl_getExtraSize,
};

int nwLevelControl_advanceSequenceTable(NwLevelControlState* state) {
    NwLevelControlData* data;
    GameObject* obj;

    data = &gNwLevelControlData;
    obj = ObjList_FindObjectById(data->targetObjectIds[state->tableIndex]);
    if (ObjTrigger_IsSetById(obj, NW_LEVEL_CONTROL_TRIGGER_ID) != 0) {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        state->mode = NW_LEVEL_CONTROL_MODE_WAIT_PARENT_SLACK;
        state->sequenceId = data->sequenceIds[state->tableIndex];
        state->nextMode = data->nextModes[state->tableIndex];
        state->tableIndex++;
        state->timerMinutes = 30;
        return 1;
    }

    if (state->tableIndex != 0) {
        obj = ObjList_FindObjectById(data->targetObjectIds[state->tableIndex - 1]);
        if (ObjTrigger_IsSetById(obj, NW_LEVEL_CONTROL_TRIGGER_ID) != 0) {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            state->mode = NW_LEVEL_CONTROL_MODE_WAIT_PARENT_SLACK;
            state->sequenceId = data->sequenceIds[state->tableIndex - 1];
            state->timerMinutes = 0;
            return 2;
        }
    }

    return 0;
}

int nwLevelControl_getExtraSize(void) {
    return sizeof(NwLevelControlState);
}

/* On free, restore the default environment fx (only if this slot's object
 * group is no longer active) and always stop the challenge timer. */
void nwLevelControl_free(GameObject* obj) {
    s8 slot = obj->anim.mapEventSlot;
    int groupStatus = (*gMapEventInterface)->getObjGroupStatus((s32)slot, 0);
    if ((u8)groupStatus == 0) {
        skySetEnvFxFlags(0);
    }
    gameTimerStop();
}

void nwLevelControl_update(GameObject* obj) {
    GameObject* player;
    u8 status;
    int sunPosition;
    int sequenceResult;
    u32 gameBit;
    u32 rescueBit;
    u8 timerRunning;
    int stateFlags;
    u32 timerActive;
    NwLevelControlState* state;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (state->hintCountdown > 0.0f) {
        gameTextShow(NW_LEVEL_CONTROL_HINT_TEXT_ID);
        state->hintCountdown -= timeDelta;
        if (state->hintCountdown < 0.0f) {
            state->hintCountdown = 0.0f;
        }
    }
    status = (*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
    if (status != 1) {
        (*gMapEventInterface)->setMapAct((int)obj->anim.mapEventSlot, 1);
    }
    status = (*gMapEventInterface)->getMapAct(7);
    if (status == 1) {
        (*gMapEventInterface)->setMapAct(7, 2);
        mainSetBits(GAMEBIT_NW_RescueBush1Cleared, 1);
        mainSetBits(GAMEBIT_NW_RescueBush2Cleared, 1);
        mainSetBits(GAMEBIT_NW_RescueBush3Cleared, 1);
        mainSetBits(GAMEBIT_NW_RescueBush4Cleared, 1);
    }
    sunPosition = (*gSkyInterface)->getSunPosition(0);
    if (sunPosition != 0) {
        if (state->dayNightMusicId != -1) {
            state->dayNightMusicId = -1;
            if (((int)state->flags & NW_LEVEL_CONTROL_FLAG_DAY_NIGHT_MUSIC) != 0) {
                Music_Trigger(NW_LEVEL_CONTROL_DAY_NIGHT_MUSIC_ID, 0);
            }
        }
    } else {
        if (state->dayNightMusicId != NW_LEVEL_CONTROL_DAY_NIGHT_MUSIC_ID) {
            state->dayNightMusicId = NW_LEVEL_CONTROL_DAY_NIGHT_MUSIC_ID;
            if (((int)state->flags & NW_LEVEL_CONTROL_FLAG_DAY_NIGHT_MUSIC) != 0) {
                Music_Trigger(NW_LEVEL_CONTROL_DAY_NIGHT_MUSIC_ID, 1);
            }
        }
    }
    GameBitLatch_Update((GameBitLatchState*)&state->flags, 8, -1, -1, 0x3a0, 0x35);
    GameBitLatch_Update((GameBitLatchState*)&state->flags, 0x10, -1, -1, 0x3a1, (int)state->dayNightMusicId);
    GameBitLatch_Update((GameBitLatchState*)&state->flags, 0x20, -1, -1, 0x393, 0x36);
    GameBitLatch_Update((GameBitLatchState*)&state->flags, 0x40, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK,
                        MUSICTRIG_PU3_Adventure_c4);
    timerActive = 0;
    gameBit = mainGetBit(GAMEBIT_SnowHornArtifact19F);
    rescueBit = mainGetBit(GAMEBIT_SnowHornArtifact19D);
    if (((rescueBit ^ gameBit) != 0) && (timerRunning = gameTimerIsRunning(), timerRunning != 0)) {
        timerActive = 1;
    }
    mainSetBits(0xf31, timerActive);
    GameBitLatch_Update((GameBitLatchState*)&state->flags, 0x80, -1, -1, 0xf31, NW_LEVEL_CONTROL_TIMER_END_MUSIC_ID);
    gameBit = mainGetBit(GAMEBIT_NW_GeyserComplete);
    if ((gameBit != 0) &&
        (status = (*gMapEventInterface)->getObjGroupStatus((int)obj->anim.mapEventSlot, NW_GEYSER_OBJECT_GROUP),
         status == 0)) {
        (*gMapEventInterface)->setObjGroupStatus((int)obj->anim.mapEventSlot, NW_GEYSER_OBJECT_GROUP, 1);
    }
    if ((((int)state->flags & NW_LEVEL_CONTROL_FLAG_TIMER_RUNNING) != 0) && isGameTimerDisabled() != 0) {
        Sfx_PlayFromObject(0, SFXTRIG_sc_lockon22);
        (*gMapEventInterface)->gotoRestartPoint();
    } else {
        switch (state->mode) {
        case NW_LEVEL_CONTROL_MODE_WAIT_START:
            gameBit = mainGetBit(GAMEBIT_SnowHornArtifact19D);
            if (gameBit != 0) {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                state->mode = NW_LEVEL_CONTROL_MODE_WALK_TABLE;
                mainSetBits(0xecd, 1);
            }
            break;
        case NW_LEVEL_CONTROL_MODE_INIT_START:
            (*gObjectTriggerInterface)->preempt((int)obj, 0x64a);
            (*gObjectTriggerInterface)->runSequence(0, obj, 0x20);
            state->mode = NW_LEVEL_CONTROL_MODE_WALK_TABLE;
            mainSetBits(0xecd, 1);
            break;
        case NW_LEVEL_CONTROL_MODE_WALK_TABLE:
            sequenceResult = nwLevelControl_advanceSequenceTable(state);
            if (sequenceResult != 0) {
                state->timerMinutes = 50;
                state->flags |= NW_LEVEL_CONTROL_FLAG_TIMER_START_PENDING;
            }
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
            nwLevelControl_advanceSequenceTable(state);
            break;
        case NW_LEVEL_CONTROL_MODE_WALK_FINAL:
            sequenceResult = nwLevelControl_advanceSequenceTable(state);
            if (sequenceResult == 1) {
                state->flags |= NW_LEVEL_CONTROL_FLAG_TIMER_COMPLETE;
            }
            break;
        case NW_LEVEL_CONTROL_MODE_WAIT_PARENT_SLACK:
            if ((player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0) {
                state->mode = NW_LEVEL_CONTROL_MODE_TIMER_STEP;
            }
            break;
        case NW_LEVEL_CONTROL_MODE_TIMER_STEP:
            if ((player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                stateFlags = state->flags;
                if ((stateFlags & NW_LEVEL_CONTROL_FLAG_TIMER_START_PENDING) != 0) {
                    state->flags = stateFlags & ~NW_LEVEL_CONTROL_FLAG_TIMER_START_PENDING;
                    state->flags |= NW_LEVEL_CONTROL_FLAG_TIMER_RUNNING;
                    gameTimerInit(NW_LEVEL_CONTROL_TIMER_ID, (u32)state->timerMinutes);
                    timerSetToCountUp();
                    (*gMapEventInterface)->savePoint(&player->anim.localPosX, (int)player->anim.rotX, 0, 0);
                } else if ((stateFlags & NW_LEVEL_CONTROL_FLAG_TIMER_COMPLETE) != 0) {
                    state->flags = stateFlags & ~NW_LEVEL_CONTROL_FLAG_TIMER_RUNNING;
                    state->flags = state->flags & ~NW_LEVEL_CONTROL_FLAG_TIMER_COMPLETE;
                    gameTimerStop();
                    Music_Trigger(NW_LEVEL_CONTROL_TIMER_END_MUSIC_ID, 0);
                    mainSetBits(GAMEBIT_SnowHornArtifact19F, 1);
                } else {
                    int extra = (int)(gameTimerGetValue() / NW_LEVEL_CONTROL_SECONDS_PER_MINUTE);
                    gameTimerStop();
                    gameTimerInit(NW_LEVEL_CONTROL_TIMER_ID, (u32)state->timerMinutes + extra);
                    timerSetToCountUp();
                }
                (*gObjectTriggerInterface)->runSequence(state->sequenceId, obj, -1);
                state->mode = state->nextMode;
            }
            break;
        case NW_LEVEL_CONTROL_MODE_CLEANUP:
            gameBit = mainGetBit(0xecd);
            if (gameBit != 0) {
                mainSetBits(0xecd, 0);
            }
            break;
        case NW_LEVEL_CONTROL_MODE_RESCUE_RETRIGGER:
            (*gObjectTriggerInterface)->preempt((int)obj, 0x5a);
            (*gObjectTriggerInterface)->runSequence(1, obj, 8);
            state->mode = NW_LEVEL_CONTROL_MODE_CLEANUP;
        }
    }
    return;
}

void nwLevelControl_init(GameObject* obj) {
    NwLevelControlData* data = &gNwLevelControlData;
    NwLevelControlState* state = obj->extra;

    Obj_GetPlayerObject();
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));

    if (mainGetBit(GAMEBIT_SnowHornArtifact19F) != 0) {
        state->mode = NW_LEVEL_CONTROL_MODE_RESCUE_RETRIGGER;
    } else if (mainGetBit(GAMEBIT_SnowHornArtifact19D) != 0) {
        state->mode = NW_LEVEL_CONTROL_MODE_INIT_START;
    } else {
        state->mode = NW_LEVEL_CONTROL_MODE_WAIT_START;
    }

    state->hintCountdown = NW_LEVEL_CONTROL_HINT_DURATION;

    skySetEnvFxRampTables(data->skyRampB, data->skyRampA, data->skyRampC, data->skyRampD);

    if (getSaveGameLoadStatus() != 0) {
        skySetEnvFxFlags(0x3f);
        getEnvfxActImmediately(0, 0, NW_LEVEL_CONTROL_ENVIRONMENT_EFFECT, 0);
    } else {
        skySetEnvFxFlags(0x1f);
        getEnvfxAct(0, 0, NW_LEVEL_CONTROL_ENVIRONMENT_EFFECT, 0);
    }

    (*gMapEventInterface)->setObjGroupStatus(7, 0, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 2, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 5, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 10, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 0x1c, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 9, 1);
}
