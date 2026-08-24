#include "dlls/objects/370_LINKB_levco.h"

#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/dll_80136a40.h"
#include "main/dll/savegame_load_api.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/mapEvent.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/render_envfx_api.h"
#include "main/sky_api.h"
#include "main/sky_interface.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define LINKB_LEVEL_CONTROL_FLAG_TRICKY_STATE 0x04
#define LINKB_LEVEL_CONTROL_FLAG_MUSIC        0x08

#define LINKB_LEVEL_CONTROL_ENVFX_ID            0x23C
#define LINKB_LEVEL_CONTROL_ENVFX_LOADED_VALUE  0x3F
#define LINKB_LEVEL_CONTROL_ENVFX_LOADING_VALUE 0x1F

#define LINKB_LEVEL_CONTROL_TRICKY_TALK_INTERVAL 2000.0f
#define LINKB_MUSIC_TRIGGER_WATER_EXIT           0x35

enum {
    LINKB_GAMEBIT_TRICKY_STATE_A = 0x1FD,
    LINKB_GAMEBIT_TRICKY_STATE_B = 0x256,
    LINKB_GAMEBIT_TRICKY_STATE_LATCH = 0x36E,
    LINKB_GAMEBIT_ALTERNATE_PATH = 0x380,
    LINKB_GAMEBIT_STAGE_1 = 0x384,
    LINKB_GAMEBIT_STAGE_2 = 0x385,
    LINKB_GAMEBIT_STAGE_3 = 0x386,
    LINKB_GAMEBIT_STAGE_4 = 0x387,
    LINKB_GAMEBIT_STAGE_5 = 0x543,
    LINKB_GAMEBIT_CITYTOMBS_MUSIC = 0xB36,
};

SkyEnvFxRampTables gLINKBLevelControlEnvFxRampTables = {
    {
        0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4,
        0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4,
    },
    {
        0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6,
        0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6, 0xB6,
    },
    {
        0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5,
        0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5, 0xB5,
    },
    {
        0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7,
        0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7, 0xB7,
    },
};

int linkbLevelControl_getExtraSize(void) {
    return sizeof(LINKBLevelControlState);
}

void linkbLevelControl_update(GameObject* obj) {
    LINKBLevelControlState* state;
    GameObject* tricky;
    GameObject* player;
    TrickyStats* trickyStats;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
    trickyStats = (*gMapEventInterface)->getTrickyStats();
    if ((*gSkyInterface)->getSunPosition(NULL) != 0) {
        if (state->musicTriggerId != -1) {
            state->musicTriggerId = -1;
            if ((state->gameBitLatch.activeMask & LINKB_LEVEL_CONTROL_FLAG_MUSIC) != 0) {
                Music_Trigger(MUSICTRIG_galleon_docks, 0);
            }
        }
    } else if (state->musicTriggerId != MUSICTRIG_galleon_docks) {
        state->musicTriggerId = MUSICTRIG_galleon_docks;
        if ((state->gameBitLatch.activeMask & LINKB_LEVEL_CONTROL_FLAG_MUSIC) != 0) {
            Music_Trigger(MUSICTRIG_galleon_docks, 1);
        }
    }

    GameBitLatch_Update(&state->gameBitLatch, 1, -1, -1, GAMEBIT_IM_WaterRelated03A0, LINKB_MUSIC_TRIGGER_WATER_EXIT);
    GameBitLatch_Update(&state->gameBitLatch, 2, -1, -1, LINKB_GAMEBIT_CITYTOMBS_MUSIC, MUSICTRIG_citytombs);
    GameBitLatch_Update(&state->gameBitLatch, LINKB_LEVEL_CONTROL_FLAG_MUSIC, -1, -1, GAMEBIT_IM_Done,
                          state->musicTriggerId);

    if ((state->gameBitLatch.activeMask & LINKB_LEVEL_CONTROL_FLAG_TRICKY_STATE) != 0) {
        if (mainGetBit(LINKB_GAMEBIT_TRICKY_STATE_A) == 0 && mainGetBit(LINKB_GAMEBIT_TRICKY_STATE_B) == 0) {
            mainSetBits(LINKB_GAMEBIT_TRICKY_STATE_LATCH, 0);
            state->gameBitLatch.activeMask &= ~LINKB_LEVEL_CONTROL_FLAG_TRICKY_STATE;
        }
    } else if (mainGetBit(LINKB_GAMEBIT_TRICKY_STATE_B) != 0 || mainGetBit(LINKB_GAMEBIT_TRICKY_STATE_A) != 0) {
        mainSetBits(LINKB_GAMEBIT_TRICKY_STATE_LATCH, 1);
        state->gameBitLatch.activeMask |= LINKB_LEVEL_CONTROL_FLAG_TRICKY_STATE;
    }

    if (tricky != NULL) {
        trickySetSoundSuppressed(tricky, 0);
        switch (state->stage) {
        case LINKB_LEVEL_CONTROL_STAGE_START:
            if (mainGetBit(LINKB_GAMEBIT_STAGE_1) != 0) {
                trickySetSoundSuppressed(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->unusedStageBits = 0;
                return;
            }
            break;
        case LINKB_LEVEL_CONTROL_STAGE_1:
            if (mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0) {
                if ((player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    mainSetBits(LINKB_GAMEBIT_STAGE_2, 1);
                    trickySetSoundSuppressed(tricky, 1);
                    (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                    state->stage++;
                    state->unusedStageBits = 0;
                    return;
                }
            }
            break;
        case LINKB_LEVEL_CONTROL_STAGE_2:
            if (trickyStats->energy != 0) {
                trickySetSoundSuppressed(tricky, 1);
                if (state->trickyHitCount-- == -1 && (tricky->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    mainSetBits(LINKB_GAMEBIT_STAGE_3, 1);
                    (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                    state->stage++;
                    state->unusedStageBits = 0;
                    return;
                }
            }
            break;
        case LINKB_LEVEL_CONTROL_STAGE_3:
            if (mainGetBit(LINKB_GAMEBIT_TRICKY_STATE_A) != 0) {
                mainSetBits(LINKB_GAMEBIT_STAGE_4, 1);
                state->stage++;
                break;
            }
            if (mainGetBit(LINKB_GAMEBIT_ALTERNATE_PATH) != 0) {
                state->alternatePath = 1;
                break;
            }
            if (state->alternatePath != 0) {
                mainSetBits(LINKB_GAMEBIT_STAGE_4, 1);
                trickySetSoundSuppressed(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->unusedStageBits = 0;
                return;
            }
            break;
        case LINKB_LEVEL_CONTROL_STAGE_4:
            if (mainGetBit(LINKB_GAMEBIT_STAGE_5) != 0) {
                trickySetSoundSuppressed(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->unusedStageBits = 0;
                return;
            }
            break;
        }
    }
    if (tricky != NULL) {
        if ((tricky->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
            state->trickyTalkTimer += timeDelta;
        }
        if (mainGetBit(GAMEBIT_TrickyTalk) == 1 && trickyStats->energy >= 4) {
            mainSetBits(GAMEBIT_TrickyTalk, 0xFF);
        }
        if (state->trickyTalkTimer >= LINKB_LEVEL_CONTROL_TRICKY_TALK_INTERVAL) {
            state->trickyTalkTimer -= LINKB_LEVEL_CONTROL_TRICKY_TALK_INTERVAL;
            if (mainGetBit(GAMEBIT_TrickyTalk) == 0xFF && trickyStats->energy < 4) {
                mainSetBits(GAMEBIT_TrickyTalk, 1);
            }
        }
    }
}

void linkbLevelControl_init(GameObject* obj) {
    u8* envFxRampBase = (u8*)(int)&gLINKBLevelControlEnvFxRampTables;
    LINKBLevelControlState* state = obj->extra;

    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
    if (mainGetBit(LINKB_GAMEBIT_TRICKY_STATE_LATCH) != 0) {
        state->gameBitLatch.activeMask &= LINKB_LEVEL_CONTROL_FLAG_TRICKY_STATE;
    }

    if (mainGetBit(LINKB_GAMEBIT_STAGE_5) != 0) {
        state->stage = LINKB_LEVEL_CONTROL_STAGE_5;
    } else if (mainGetBit(LINKB_GAMEBIT_STAGE_4) != 0) {
        state->stage = LINKB_LEVEL_CONTROL_STAGE_4;
    } else if (mainGetBit(LINKB_GAMEBIT_STAGE_3) != 0) {
        state->stage = LINKB_LEVEL_CONTROL_STAGE_3;
    } else if (mainGetBit(LINKB_GAMEBIT_STAGE_2) != 0) {
        state->stage = LINKB_LEVEL_CONTROL_STAGE_2;
    } else if (mainGetBit(LINKB_GAMEBIT_STAGE_1) != 0) {
        state->stage = LINKB_LEVEL_CONTROL_STAGE_1;
    }

    skySetEnvFxRampTables(envFxRampBase + 0x38, (u8*)(int)&gLINKBLevelControlEnvFxRampTables, envFxRampBase + 0x70,
                          envFxRampBase + 0xA8);
    if (getSaveGameLoadStatus() != 0) {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, 0) == 0) {
            skySetEnvFxFlags(LINKB_LEVEL_CONTROL_ENVFX_LOADED_VALUE);
        }
        getEnvfxActImmediately(NULL, NULL, LINKB_LEVEL_CONTROL_ENVFX_ID, 0);
    } else {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, 0) == 0) {
            skySetEnvFxFlags(LINKB_LEVEL_CONTROL_ENVFX_LOADING_VALUE);
        }
        getEnvfxAct(NULL, NULL, LINKB_LEVEL_CONTROL_ENVFX_ID, 0);
    }

    state->musicTriggerId = 0;
}

ObjectDescriptor gLINKBLevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)linkbLevelControl_init,
    (ObjectDescriptorCallback)linkbLevelControl_update,
    0,
    0,
    0,
    0,
    linkbLevelControl_getExtraSize,
};
