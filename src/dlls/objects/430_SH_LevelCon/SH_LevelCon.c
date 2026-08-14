/*
 * shlevelcontrol (DLL 0x1AE) - the SnowHorn / ThornTail Hollow area level
 * controller object.
 *
 * SH_LevelControl_update is the area's per-frame script driver: it keeps
 * the day/night music in sync (SH_LevelControl_setMusic + the
 * GameBitLatch helpers), mirrors a set of game bits onto map-event
 * object-group statuses, and dispatches the active sub-event by the
 * map-event act: early cutscenes, the ThornTail egg events, the
 * timed "bloop" collection minigame (air meter), and the env-fx / sky
 * weather sets. SH_LevelControl_sequenceCallback drives the staged map/object-group
 * teardown. init seeds the music latches and clears the bloop bits.
 */
#include "dlls/objects/430_SH_LevelCon.h"

#include "dolphin/pad.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/debug.h"
#include "main/dll/player_api.h"
#include "main/dll/savegame_load_api.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/gametext_show_api.h"
#include "main/map_load.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/pad.h"
#include "main/pad_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/screen_transition.h"
#include "main/sky.h"
#include "main/sky_api.h"
#include "main/sky_interface.h"
#include "sys/objects.h"

#define SH_LEVELCONTROL_FLAG_REFRESH_MAP 0x2 /* re-apply map music on next tick; cleared at substate/music transitions */
#define SH_LEVELCONTROL_FLAG_THORNTAIL_TRIGGERED 0x40 /* ThornTail intro event already fired */
#define SH_LEVELCONTROL_FLAG_EARLY_SCENE_STARTED 0x80 /* early cutscene sequence begun */

/* env-effect ids replayed per weather/time state gate (index-style; roles opaque).
   A/D shared across the states; B/C exclusive to the 0xd36 gate; E/F to the 0xd35 gate. */
#define SHLEVELCONTROL_ENVFX_A 0x1bf
#define SHLEVELCONTROL_ENVFX_B 0x231
#define SHLEVELCONTROL_ENVFX_C 0x232
#define SHLEVELCONTROL_ENVFX_D 0x244
#define SHLEVELCONTROL_ENVFX_E 0x1be
#define SHLEVELCONTROL_ENVFX_F 0x1c0

#define SH_LEVELCONTROL_MAP_COUNTDOWN_RESET  5
#define SH_LEVELCONTROL_MAP_COUNTDOWN_ENABLE 1
#define SH_LEVELCONTROL_MAP_UNLOAD_FLAGS       0x20000000
#define SHLEVELCONTROL_AIRMETER_BGTEXTURE    0x5db /* air-meter background texture id */


void SH_LevelControl_setMusic(short* state);

typedef struct ShLevelControlTables {
    s16 bloopGameBits[18]; /* bloop-minigame collected game bits */
    s16 skyRampA[28];      /* env-fx ramp, passed 2nd to skySetEnvFxRampTables (base+0x24) */
    s16 skyRampB[28];      /* env-fx ramp, passed 1st to skySetEnvFxRampTables (base+0x5c) */
    s16 skyRampC[28];      /* env-fx ramp, passed 3rd to skySetEnvFxRampTables (base+0x94) */
    s16 skyRampD[28];      /* env-fx ramp, passed 4th to skySetEnvFxRampTables (base+0xcc) */
} ShLevelControlTables;

STATIC_ASSERT(sizeof(ShLevelControlTables) == 0x104);
STATIC_ASSERT(offsetof(ShLevelControlTables, bloopGameBits) == 0x00);
STATIC_ASSERT(offsetof(ShLevelControlTables, skyRampA) == 0x24);
STATIC_ASSERT(offsetof(ShLevelControlTables, skyRampB) == 0x5C);
STATIC_ASSERT(offsetof(ShLevelControlTables, skyRampC) == 0x94);
STATIC_ASSERT(offsetof(ShLevelControlTables, skyRampD) == 0xCC);

ShLevelControlTables gShLevelControlTables = {
    {5, 8, 19, 20, 146, 147, 153, 174, 175, 176, 190, 417, 196, 197, 198, 245, 260, 277},
    {434, 97,  97,  97,  434, 437, 440, 440, 434, 97, 97,  97, 97, 97,
     437, 440, 440, 440, 434, 97,  97,  97,  97,  97, 434, 97, 97, 97},
    {435, 95,  95,  95,  435, 438, 441, 441, 435, 95, 95,  95, 95, 95,
     438, 441, 441, 441, 435, 95,  95,  95,  95,  95, 435, 95, 95, 95},
    {436, 96,  96,  96,  436, 439, 442, 442, 436, 96, 96,  96, 96, 96,
     439, 442, 442, 442, 436, 96,  96,  96,  96,  96, 436, 96, 96, 96},
    {-1, -1,  -1, -1,  -1, -1, 424, -1, -1, -1, -1, -1, -1, -1,
     -1, 424, -1, 424, -1, -1, -1,  -1, -1, -1, -1, -1, -1, -1}};
ObjectDescriptor gSH_LevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SH_LevelControl_init,
    (ObjectDescriptorCallback)SH_LevelControl_update,
    0,
    0,
    (ObjectDescriptorCallback)SH_LevelControl_free,
    0,
    SH_LevelControl_getExtraSize,
};

char sShLevelControlNumBloopsFormat[] = "numBloops %d\n";

int SH_LevelControl_getExtraSize(void) {
    return sizeof(ShLevelControlState);
}

void SH_LevelControl_free(void) {
    skySetEnvFxFlags(0);
    if (mainGetBit(GAMEBIT_ITEM_BigScarabBag_Got) == 0) {
        (*gGameUIInterface)->airMeterSetShutdown();
    }
    if (mainGetBit(GAMEBIT_ITEM_MoonPassKey_Got) != 0) {
        mainSetBits(GAMEBIT_ITEM_FireWeed_Count, 0);
    }
}

int SH_LevelControl_sequenceCallback(void* obj, void* unused, ObjSeqState* updateState) {
    GameObject* puzzleObj;
    int i;
    puzzleObj = (GameObject*)obj;
    i = 0;
    while (i < updateState->eventCount) {
        switch (updateState->eventIds[i]) {
        case 0:
            SH_LevelControl_setMusic((short*)puzzleObj->extra);
            break;
        }
        i++;
    }
    SH_LevelControl_updateTotemPuzzleMapState(obj, puzzleObj->extra);
    return 0;
}

void SH_LevelControl_updateTotemPuzzleMapState(void* obj, void* state) {
    GameObject* puzzleObj;
    ShLevelControlState* runtime;
    puzzleObj = (GameObject*)obj;
    runtime = (ShLevelControlState*)state;

    if (mainGetBit(GAMEBIT_SH_initObjGroups) != 0) {
        runtime->mapEventCountdown = SH_LEVELCONTROL_MAP_COUNTDOWN_RESET;
        mainSetBits(GAMEBIT_SH_initObjGroups, 0);
    }
    if (runtime->mapEventCountdown == 0) {
        return;
    }

    if (runtime->mapEventCountdown == SH_LEVELCONTROL_MAP_COUNTDOWN_RESET) {
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 1, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 4, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 6, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 7, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 8, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 9, 0);
        mapUnload(0x13, SH_LEVELCONTROL_MAP_UNLOAD_FLAGS);
        mapUnload(0x41, SH_LEVELCONTROL_MAP_UNLOAD_FLAGS);
        mapUnload(0x43, SH_LEVELCONTROL_MAP_UNLOAD_FLAGS);
        mapUnload(0x45, SH_LEVELCONTROL_MAP_UNLOAD_FLAGS);
    }
    if (runtime->mapEventCountdown == SH_LEVELCONTROL_MAP_COUNTDOWN_ENABLE) {
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 0, 1);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 2, 1);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 3, 1);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 5, 1);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->anim.mapEventSlot, 0xa, 1);
    }
    runtime->mapEventCountdown--;
}

void GameBitLatch_Update(GameBitLatchState* state, int mask, s16 clearIfSetBit, s16 clearIfClearBit, s16 latchBit,
                           int musicId) {
    u8 clearIfSetBitValid = clearIfSetBit != -1;
    u8 clearIfClearBitValid = clearIfClearBit != -1;

    if ((state->activeMask & mask) != 0) {
        if (clearIfSetBitValid == 0 || mainGetBit(clearIfSetBit) == 0) {
            if (mainGetBit(latchBit) != 0) {
                return;
            }
        }
        if (clearIfSetBitValid != 0) {
            mainSetBits(clearIfSetBit, 0);
        }
        if (clearIfClearBitValid != 0) {
            mainSetBits(clearIfClearBit, 0);
        }
        mainSetBits(latchBit, 0);
        if (musicId != -1) {
            Music_Trigger(musicId, 0);
        }
        state->activeMask = state->activeMask & ~mask;
    } else {
        if (clearIfClearBitValid == 0 || mainGetBit(clearIfClearBit) == 0) {
            if (mainGetBit(latchBit) == 0) {
                return;
            }
        }
        if (clearIfSetBitValid != 0) {
            mainSetBits(clearIfSetBit, 0);
        }
        if (clearIfClearBitValid != 0) {
            mainSetBits(clearIfClearBit, 0);
        }
        mainSetBits(latchBit, 1);
        if (musicId != -1) {
            Music_Trigger(musicId, 1);
        }
        state->activeMask = state->activeMask | mask;
    }
}

void GameBitLatch_UpdateInverted(GameBitLatchState* state, int mask, s16 clearIfSetBit, s16 clearIfClearBit,
                                   s16 latchBit, int musicId) {
    mainSetBits(latchBit, !mainGetBit(latchBit));
    GameBitLatch_Update(state, mask, clearIfSetBit, clearIfClearBit, latchBit, musicId);
    mainSetBits(latchBit, !mainGetBit(latchBit));
}

void SH_LevelControl_setMusic(short* obj) {
    if ((*gSkyInterface)->getSunPosition(0) != 0) {
        if (obj[8] == 0x39 || obj[8] == -1) {
            obj[8] = 0x2d;
            if ((*(int*)obj & 1) != 0) {
                Music_Trigger(MUSICTRIG_nightjungle, 0);
                Music_Trigger(MUSICTRIG_PU1_Mysterious, 1);
            }
        }
        if (obj[9] == 0xc2 || obj[9] == -1) {
            obj[9] = 0xce;
            if ((*(int*)obj & 2) != 0) {
                Music_Trigger(MUSICTRIG_cldrnr_walkabout, 0);
                Music_Trigger(MUSICTRIG_CRF_Swim, 1);
            }
        }
    } else {
        if (obj[8] == 0x2d || obj[8] == -1) {
            obj[8] = 0x39;
            if ((*(int*)obj & 1) != 0) {
                Music_Trigger(MUSICTRIG_PU1_Mysterious, 0);
                Music_Trigger(MUSICTRIG_nightjungle, 1);
            }
        }
        if (obj[9] == 0xce || obj[9] == -1) {
            obj[9] = 0xc2;
            if ((*(int*)obj & 2) != 0) {
                Music_Trigger(MUSICTRIG_CRF_Swim, 0);
                Music_Trigger(MUSICTRIG_cldrnr_walkabout, 1);
            }
        }
    }
    if (mainGetBit(GAMEBIT_SH_TalkedToPepper) != 0) {
        if (mainGetBit(GAMEBIT_SH_Landed064B) != 0) {
            mainSetBits(GAMEBIT_KrazTest1Related0390, 1);
        }
        GameBitLatch_Update((GameBitLatchState*)obj, 1, 0x1a7, GAMEBIT_SH_Landed064B, GAMEBIT_KrazTest1Related0372,
                              obj[8]);
        GameBitLatch_Update((GameBitLatchState*)obj, 2, GAMEBIT_SH_WarpStoneRelated01A8, GAMEBIT_SH_Entered00C0,
                              GAMEBIT_KrazTest1Related0390, obj[9]);
        GameBitLatch_Update((GameBitLatchState*)obj, 4, -1, -1, 0x393, 0x36);
        GameBitLatch_Update((GameBitLatchState*)obj, 8, -1, -1, 0xa32, 0x98);
        GameBitLatch_Update((GameBitLatchState*)obj, 0x10, -1, -1, 0xbfe, 0xc3);
    }
}

void SH_LevelControl_runBloopEvent(GameObject* obj, ShLevelControlState* state) {
    GameObject* player;
    u8 i;
    u8 bloopsRemaining;
    u8 j;

    if (((u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, 0) == 0) &&
        (mainGetBit(GAMEBIT_ITEM_BigScarabBag_Got) == 0)) {
        state->bloopEventState = 0;
        (*gGameUIInterface)->airMeterSetShutdown();
        for (j = 0; j < 0x12; j++) {
            mainSetBits(gShLevelControlTables.bloopGameBits[j], 0);
        }
    }

    player = Obj_GetPlayerObject();
    switch (state->bloopEventState) {
    case 0:
        if (mainGetBit(GAMEBIT_ITEM_BigScarabBag_Got) != 0) {
            state->bloopEventState = 7;
        } else {
            state->bloopEventState = 1;
        }
        break;
    case 1:
        if (mainGetBit(0x124) != 0) {
            (*gMapEventInterface)->savePoint(&player->anim.localPosX, player->anim.rotX, 1, 0);
            state->airMeterTimer = 100000.0f;
            (*gGameUIInterface)->initAirMeter(100000, SHLEVELCONTROL_AIRMETER_BGTEXTURE);
            state->bloopEventState = 2;
        }
        break;
    case 2:
        bloopsRemaining = 0x12;
        for (i = 0; i < 0x12; i++) {
            if (mainGetBit(gShLevelControlTables.bloopGameBits[i]) != 0) {
                bloopsRemaining--;
            }
        }
        logPrintf(sShLevelControlNumBloopsFormat, bloopsRemaining);
        if (bloopsRemaining == 0) {
            (*gGameUIInterface)->airMeterSetShutdown();
            (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_BLACK);
            state->bloopEventState = 3;
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
        } else {
            state->airMeterTimer -= bloopsRemaining * timeDelta;
            if (state->airMeterTimer >= 0.0f) {
                (*gGameUIInterface)->runAirMeter((int)state->airMeterTimer);
            } else if ((u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, 0) != 0) {
                (*gGameUIInterface)->airMeterSetShutdown();
                (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_BLACK);
                state->bloopEventState = 5;
            } else {
                state->airMeterTimer = 0.0f;
                (*gGameUIInterface)->runAirMeter(1);
            }
        }
        break;
    case 3:
        if (((*gScreenTransitionInterface)->isFinished() != 0) &&
            ((((GameObject*)Obj_GetPlayerObject())->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)) {
            mainSetBits(GAMEBIT_ITEM_BigScarabBag_Got, 1);
            (*gObjectTriggerInterface)->runSequence(3, (void*)obj, -1);
            state->bloopEventState = 4;
        }
        break;
    case 4:
        state->bloopEventState = 7;
        break;
    case 5:
        if (((*gScreenTransitionInterface)->isFinished() != 0) &&
            ((((GameObject*)Obj_GetPlayerObject())->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)) {
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
            state->bloopEventState = 6;
        }
        break;
    case 6:
        (*gMapEventInterface)->gotoRestartPoint();
        break;
    case 7:
        if (mainGetBit(GAMEBIT_ToldGetSnowHornArtifact) == 0) {
            mainSetBits(GAMEBIT_ToldGetSnowHornArtifact, 1);
            if (mainGetBit(GAMEBIT_ITEM_NWSnowHornArtifact_Got) == 0) {
                mainSetBits(GAMEBIT_IncomingCommunication, 1);
            }
        }
        break;
    }

    if (state->bloopEventState == 2) {
        if (state->musicLatch != 0xf2) {
            state->musicLatch = 0xf2;
            mainSetBits(GAMEBIT_SH_Entered00C0, 1);
            state->flags &= ~SH_LEVELCONTROL_FLAG_REFRESH_MAP;
        }
    } else if (state->musicLatch != 0xcc) {
        state->musicLatch = 0xcc;
        mainSetBits(GAMEBIT_SH_Entered00C0, 1);
        state->flags &= ~SH_LEVELCONTROL_FLAG_REFRESH_MAP;
    }

    if ((mainGetBit(GAMEBIT_SH_Give200ScarabBag) == 0) && (mainGetBit(GAMEBIT_ITEM_200ScarabBag_Got) != 0)) {
        mainSetBits(GAMEBIT_SH_Give200ScarabBag, 1);
        (*gMapEventInterface)->savePoint(NULL, 0, 1, 0);
    }
}

#define SHOPKEEPER_THORNTAIL_OBJECT_ID 0x442ff

#define SHOPKEEPER_APPLY_MAP_OVERRIDE(state, enabledBit)                                                               \
    if (mainGetBit((enabledBit)) != 0) {                                                                               \
        if ((state)->mapOverride != 0xcc) {                                                                            \
            (state)->mapOverride = 0xcc;                                                                               \
            mainSetBits(GAMEBIT_SH_Entered00C0, 1);                                                                    \
            (state)->storyFlags &= ~SH_LEVELCONTROL_FLAG_REFRESH_MAP;                                                    \
        }                                                                                                              \
    } else if ((state)->mapOverride == 0xcc) {                                                                         \
        (state)->mapOverride = -1;                                                                                     \
    }

void SH_LevelControl_doThornTailEvents(void* obj, ShLevelControlState* state) {
    GameObject* thornTailObj;
    GameObject* playerObj;

    SHOPKEEPER_APPLY_MAP_OVERRIDE(state, GAMEBIT_ITEM_MoonPassKey_Got);

    switch (state->thornTailState) {
    case 0:
        if (mainGetBit(GAMEBIT_SH_BloopEventDone) != 0) {
            state->thornTailState = 7;
        } else {
            (*gObjectTriggerInterface)->runSequence(5, obj, -1);
            state->thornTailState = 1;
        }
        break;
    case 1:
        thornTailObj = (GameObject*)ObjList_FindObjectById(SHOPKEEPER_THORNTAIL_OBJECT_ID);
        if ((thornTailObj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
            playerObj = (GameObject*)Obj_GetPlayerObject();
            if ((playerObj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                (*gObjectTriggerInterface)->runSequence(6, obj, -1);
                state->thornTailState = 7;
                mainSetBits(GAMEBIT_SH_BloopEventDone, 1);
            }
        }
        break;
    case 7:
        break;
    }

    if ((state->storyFlags & SH_LEVELCONTROL_FLAG_THORNTAIL_TRIGGERED) == 0 && mainGetBit(GAMEBIT_SH_FireWeed_190) != 0 &&
        mainGetBit(GAMEBIT_SH_FireWeed_191) != 0 && mainGetBit(GAMEBIT_SH_FireWeed_192) != 0) {
        if (mainGetBit(GAMEBIT_ITEM_MoonPassKey_Got) == 0) {
            thornTailObj = (GameObject*)ObjList_FindObjectById(SHOPKEEPER_THORNTAIL_OBJECT_ID);
            if (thornTailObj != 0) {
                playerObj = (GameObject*)Obj_GetPlayerObject();
                if ((playerObj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    if (isScreenTransitionActive() != 0) {
                        mainSetBits(GAMEBIT_ITEM_MoonPassKey_Got, 1);
                        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                        state->storyFlags |= SH_LEVELCONTROL_FLAG_THORNTAIL_TRIGGERED;
                    } else {
                        mainSetBits(GAMEBIT_ITEM_MoonPassKey_Got, 1);
                        (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_BLACK);
                    }
                }
            }
        } else if ((*gScreenTransitionInterface)->isFinished() != 0) {
            thornTailObj = (GameObject*)ObjList_FindObjectById(SHOPKEEPER_THORNTAIL_OBJECT_ID);
            if (thornTailObj != 0) {
                playerObj = (GameObject*)Obj_GetPlayerObject();
                if ((playerObj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    state->storyFlags |= SH_LEVELCONTROL_FLAG_THORNTAIL_TRIGGERED;
                }
            }
        }
    }

    if (mainGetBit(GAMEBIT_SH_GiveMoonPassKey) == 0 && mainGetBit(GAMEBIT_ITEM_MMPKey_Got) != 0) {
        mainSetBits(GAMEBIT_SH_GiveMoonPassKey, 1);
        (*gMapEventInterface)->savePoint(NULL, 0, 1, 0);
    }
}

void SH_LevelControl_doEarlyScenes(GameObject* obj, ShLevelControlState* state) {
    GameObject* playerObj;

    SHOPKEEPER_APPLY_MAP_OVERRIDE(state, GAMEBIT_SH_MetQueen);

    if (state->earlySceneDelay >= 2) {
        if (mainGetBit(GAMEBIT_SH_TalkedToPepper) == 0) {
            padClearAnalogInputX(0);
            padClearAnalogInputY(0);
            buttonDisable(0, PAD_BUTTON_A);
            buttonDisable(0, PAD_BUTTON_B);
            buttonDisable(0, PAD_BUTTON_MENU);
            playerObj = (GameObject*)Obj_GetPlayerObject();
            if ((playerObj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                mainSetBits(GAMEBIT_SH_TalkedToPepper, 1);
            }
        }

        if ((state->storyFlags & SH_LEVELCONTROL_FLAG_EARLY_SCENE_STARTED) == 0) {
            mainSetBits(GAMEBIT_ENV_dayNo, 0);
            state->storyFlags |= SH_LEVELCONTROL_FLAG_EARLY_SCENE_STARTED;
        }
    } else {
        state->earlySceneDelay++;
    }

    if (mainGetBit(GAMEBIT_STAFF_TUTORIAL_ARENA_CLEARED) == 0 &&
        mainGetBit(GAMEBIT_STAFF_TUTORIAL_SHARPCLAW_DEAD_3) != 0 &&
        mainGetBit(GAMEBIT_STAFF_TUTORIAL_SHARPCLAW_DEAD_4) != 0 &&
        mainGetBit(GAMEBIT_STAFF_TUTORIAL_SHARPCLAW_DEAD_1) != 0 &&
        mainGetBit(GAMEBIT_STAFF_TUTORIAL_SHARPCLAW_DEAD_2) != 0) {
        playerObj = (GameObject*)Obj_GetPlayerObject();
        if ((playerObj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
            mainSetBits(GAMEBIT_STAFF_TUTORIAL_ARENA_CLEARED, 1);
        }
    }

    if ((u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, 6) == 0) {
        playerObj = (GameObject*)Obj_GetPlayerObject();
        if (playerHasSpell(playerObj, 0) != 0) {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 6, 1);
        }
    }
}

void SH_LevelControl_update(GameObject* obj) {
    ShLevelControlState* state;
    u32 val;
    u32 val2;
    u32 val3;
    GameObject* player;
    u8 animEvt;
    u8* base = (u8*)&gShLevelControlTables;

    state = (obj)->extra;
    if (state->hudTextTimer > 0.0f) {
        gameTextShow(0x3f6);
        state->hudTextTimer = state->hudTextTimer - timeDelta;
        if (state->hudTextTimer < 0.0f) {
            state->hudTextTimer = 0.0f;
        }
    }
    SH_LevelControl_setMusic((short*)state);
    val = mainGetBit(GAMEBIT_SH_Related03AA);
    if (val != 0) {
        if ((obj)->anim.mapEventSlot == 8) {
            animEvt = (*gMapEventInterface)->getObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1d);
            if (animEvt == '\0') {
                (*gMapEventInterface)->setObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1d, 1);
            }
        } else {
            animEvt = (*gMapEventInterface)->getObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1d);
            if (animEvt != '\0') {
                (*gMapEventInterface)->setObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1d, 0);
            }
        }
    }
    val = mainGetBit(GAMEBIT_STAFF_PICKUP_MAP_UNLOADED);
    if (val != 0) {
        animEvt = (*gMapEventInterface)->getObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1c);
        if (animEvt == '\0') {
            (*gMapEventInterface)->setObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1c, 1);
        }
    } else {
        animEvt = (*gMapEventInterface)->getObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1c);
        if (animEvt != '\0') {
            (*gMapEventInterface)->setObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1c, 0);
        }
    }
    val = mainGetBit(GAMEBIT_STAFF_TUTORIAL_ARENA_REWARD_UNLOCKED);
    if ((val != 0) &&
        (animEvt = (*gMapEventInterface)->getObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1b), animEvt == '\0')) {
        (*gMapEventInterface)->setObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1b, 1);
    }
    val = mainGetBit(GAMEBIT_STAFF_TUTORIAL_ARENA_ACTIVE);
    if (val != 0) {
        animEvt = (*gMapEventInterface)->getObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1a);
        if (animEvt == '\0') {
            (*gMapEventInterface)->setObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1a, 1);
        }
    } else {
        animEvt = (*gMapEventInterface)->getObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1a);
        if (animEvt != '\0') {
            (*gMapEventInterface)->setObjGroupStatus((int)(obj)->anim.mapEventSlot, 0x1a, 0);
        }
    }
    switch (state->mapAct) {
    case 1:
        SH_LevelControl_doEarlyScenes(obj, state);
        break;
    case 2:
        val = mainGetBit(GAMEBIT_SH_ReturnedToQueen);
        if ((val != 0) && (val3 = mainGetBit(GAMEBIT_ITEM_WhiteGrubTub_Used), val3 < 6)) {
            if (state->musicLatch != 0xdb) {
                state->musicLatch = 0xdb;
                mainSetBits(GAMEBIT_SH_Entered00C0, 1);
                state->flags &= ~SH_LEVELCONTROL_FLAG_REFRESH_MAP;
            }
        } else {
            val = mainGetBit(GAMEBIT_ITEM_WhiteGrubTub_Used);
            if ((val == 6) && (state->musicLatch != 0xcc)) {
                state->musicLatch = 0xcc;
                mainSetBits(GAMEBIT_SH_Entered00C0, 1);
                state->flags &= ~SH_LEVELCONTROL_FLAG_REFRESH_MAP;
            }
        }
        val = mainGetBit(GAMEBIT_ITEM_WhiteGrubTub_Used);
        val2 = mainGetBit(GAMEBIT_ITEM_WhiteShroom_Count);
        if ((val2 + val == 6) && (val = mainGetBit(GAMEBIT_SH_Got6WhiteShrooms), val == 0)) {
            Sfx_PlayFromObject(obj, SFXTRIG_mpick1_b);
            mainSetBits(GAMEBIT_SH_Got6WhiteShrooms, 1);
        }
        break;
    case 3:
        SH_LevelControl_doThornTailEvents(obj, state);
        break;
    case 4:
        if (state->musicLatch != 0xcc) {
            state->musicLatch = 0xcc;
            mainSetBits(GAMEBIT_SH_Entered00C0, 1);
            state->flags &= ~SH_LEVELCONTROL_FLAG_REFRESH_MAP;
        }
        if (state->waitCounter >= 2) {
            val = mainGetBit(GAMEBIT_SH_PushedSwitchInWell);
            if (val == 0) {
                padClearAnalogInputX(0);
                padClearAnalogInputY(0);
                buttonDisable(0, PAD_BUTTON_A);
                buttonDisable(0, PAD_BUTTON_B);
                buttonDisable(0, PAD_BUTTON_MENU);
                player = Obj_GetPlayerObject();
                if ((player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    (*gObjectTriggerInterface)->runSequence(7, (void*)obj, 0xffffffff);
                    mainSetBits(GAMEBIT_SH_PushedSwitchInWell, 1);
                }
            } else {
                val = mainGetBit(GAMEBIT_SH_Related0EDE);
                if (val == 0) {
                    mainSetBits(GAMEBIT_SH_Related0EDE, 1);
                    mainSetBits(GAMEBIT_IncomingCommunication, 1);
                }
            }
        } else {
            state->waitCounter += 1;
        }
        break;
    case 5:
        val = mainGetBit(GAMEBIT_SH_Related023C);
        if (val != 0) {
            if (state->musicLatch != 0xcc) {
                state->musicLatch = 0xcc;
                mainSetBits(GAMEBIT_SH_Entered00C0, 1);
                state->flags &= ~SH_LEVELCONTROL_FLAG_REFRESH_MAP;
            }
        } else if (state->musicLatch == 0xcc) {
            state->musicLatch = -1;
        }
        val = mainGetBit(GAMEBIT_SH_Related0090);
        if (((val != 0) && (val = mainGetBit(GAMEBIT_SH_Related0EB3), val == 0)) &&
            (player = Obj_GetPlayerObject(), (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)) {
            mainSetBits(GAMEBIT_SH_Related0EB3, 1);
        }
        break;
    case 6:
        SH_LevelControl_runBloopEvent(obj, state);
        break;
    case 7:
        val = mainGetBit(GAMEBIT_SH_ThornTailRelated01A0);
        if (val != 0) {
            if (state->musicLatch != 0xcc) {
                state->musicLatch = 0xcc;
                mainSetBits(GAMEBIT_SH_Entered00C0, 1);
                state->flags &= ~SH_LEVELCONTROL_FLAG_REFRESH_MAP;
            }
        } else if (state->musicLatch == 0xcc) {
            state->musicLatch = -1;
        }
        if (state->waitCounter >= 2) {
            val = mainGetBit(GAMEBIT_SH_Related0177);
            if (val == 0) {
                padClearAnalogInputX(0);
                padClearAnalogInputY(0);
                buttonDisable(0, PAD_BUTTON_A);
                buttonDisable(0, PAD_BUTTON_B);
                buttonDisable(0, PAD_BUTTON_MENU);
                player = Obj_GetPlayerObject();
                if ((player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    (*gObjectTriggerInterface)->runSequence(4, (void*)obj, 0xffffffff);
                    mainSetBits(GAMEBIT_SH_Related0177, 1);
                }
            }
        } else {
            state->waitCounter += 1;
        }
        break;
    case 8:
        if (state->musicLatch != 0xcc) {
            state->musicLatch = 0xcc;
            mainSetBits(GAMEBIT_SH_Entered00C0, 1);
            state->flags &= ~SH_LEVELCONTROL_FLAG_REFRESH_MAP;
        }
        val = mainGetBit(GAMEBIT_SH_ReturnedAfter4thStone);
        if ((val != 0) && (val = mainGetBit(GAMEBIT_SH_ToldGetViewFinder), val == 0)) {
            mainSetBits(GAMEBIT_SH_ToldGetViewFinder, 1);
            val = mainGetBit(GAMEBIT_ITEM_Viewfinder_Got);
            if (val == 0) {
                mainSetBits(GAMEBIT_IncomingCommunication, 1);
            }
        }
    }
    val = mainGetBit(GAMEBIT_SH_Related0D36);
    if (val != 0) {
        if ((obj)->userData2 != 2) {
            (obj)->userData2 = 2;
            skySetEnvFxFlags(0);
            if ((obj)->userData1 == 2) {
                getEnvfxActImmediately(0, 0, SHLEVELCONTROL_ENVFX_A, 0);
                getEnvfxActImmediately(0, 0, SHLEVELCONTROL_ENVFX_B, 0);
                getEnvfxActImmediately(0, 0, SHLEVELCONTROL_ENVFX_C, 0);
                getEnvfxActImmediately(0, 0, SHLEVELCONTROL_ENVFX_D, 0);
            } else {
                getEnvfxAct(0, 0, SHLEVELCONTROL_ENVFX_A, 0);
                getEnvfxAct(0, 0, SHLEVELCONTROL_ENVFX_B, 0);
                getEnvfxAct(0, 0, SHLEVELCONTROL_ENVFX_C, 0);
                getEnvfxAct(0, 0, SHLEVELCONTROL_ENVFX_D, 0);
            }
        }
    } else {
        val = mainGetBit(GAMEBIT_SH_Related0D35);
        if (val != 0) {
            if ((obj)->userData2 != 1) {
                (obj)->userData2 = 1;
                if ((obj)->userData1 == 2) {
                    skySetEnvFxFlags(0);
                    getEnvfxActImmediately(0, 0, SHLEVELCONTROL_ENVFX_A, 0);
                    getEnvfxActImmediately(0, 0, SHLEVELCONTROL_ENVFX_E, 0);
                    getEnvfxActImmediately(0, 0, SHLEVELCONTROL_ENVFX_F, 0);
                    getEnvfxActImmediately(0, 0, SHLEVELCONTROL_ENVFX_D, 0);
                } else {
                    skySetEnvFxFlags(0);
                    getEnvfxAct(0, 0, SHLEVELCONTROL_ENVFX_A, 0);
                    getEnvfxAct(0, 0, SHLEVELCONTROL_ENVFX_E, 0);
                    getEnvfxAct(0, 0, SHLEVELCONTROL_ENVFX_F, 0);
                    getEnvfxAct(0, 0, SHLEVELCONTROL_ENVFX_D, 0);
                }
            }
        } else if ((obj)->userData2 != 0) {
            (obj)->userData2 = 0;
            if ((obj)->userData1 == 2) {
                skySetEnvFxRampTables(&base[0x5c], &base[0x24], &base[0x94], &base[0xcc]);
                skySetEnvFxFlags(0x3f);
                getEnvfxActImmediately(0, 0, SHLEVELCONTROL_ENVFX_D, 0);
                skySetLightIndex(0, 0.0f);
            } else {
                skySetEnvFxRampTables(&base[0x5c], &base[0x24], &base[0x94], &base[0xcc]);
                skySetEnvFxFlags(0x1f);
                getEnvfxAct(0, 0, SHLEVELCONTROL_ENVFX_D, 0);
            }
        }
    }
    SH_LevelControl_updateTotemPuzzleMapState((void*)obj, state);
    return;
}

void SH_LevelControl_init(GameObject* obj) {
    ShLevelControlState* state = obj->extra;
    int i;
    u32 objectFlags;

    obj->animEventCallback = SH_LevelControl_sequenceCallback;
    objectFlags = obj->objectFlags | OBJECT_OBJFLAG_HIDDEN;
    obj->objectFlags = objectFlags;
    obj->userData2 = 3;

    if (getSaveGameLoadStatus() != 0) {
        obj->userData1 = 2;
    } else {
        obj->userData1 = 1;
    }

    state->dayNightMusicLatch = -1;
    state->hudTextTimer = 300.0f;

    if (mainGetBit(GAMEBIT_ITEM_MMPKey_Got) != 0) {
        state->flags |= SH_LEVELCONTROL_FLAG_THORNTAIL_TRIGGERED;
    }

    state->mapAct = (*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);

    state->musicLatch = -1;
    Music_Trigger(MUSICTRIG_fox_arwing, 0);
    Music_Trigger(MUSICTRIG_Barrels, 0);
    Music_Trigger(MUSICTRIG_PU3_Adventure_b2, 0);
    Music_Trigger(MUSICTRIG_PU3_Adventure_c4, 0);
    Music_Trigger(MUSICTRIG_wcity_day, 0);
    Music_Trigger(MUSICTRIG_trex_boss_1, 0);
    Music_Trigger(MUSICTRIG_drako_3, 0);
    mainSetBits(GAMEBIT_ITEM_PDA_Got, 1);

    if (mainGetBit(GAMEBIT_ITEM_BigScarabBag_Got) == 0) {
        for (i = 0; i < 18; i++) {
            mainSetBits(gShLevelControlTables.bloopGameBits[i], 0);
        }
    }
    Rcp_DisableHeatEffect();
}
