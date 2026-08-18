/* Ice Mountain event and world-map controller. */
#include "dlls/objects/361_IMIceMounta.h"

#include "dlls/objects/common/vehicle.h"

#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/cloudaction_interface.h"
#include "main/dll/dll_0011_screens.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gametext_color_api.h"
#include "main/gametext_show_api.h"
#include "main/mapEventTypes.h"
#include "main/map_load.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/render_lactions_api.h"
#include "main/sky_interface.h"
#include "sys/objects.h"

#define IM_ICE_MOUNTAIN_PLAYER_MODE_WORLDMAP 1
#define IM_ICE_MOUNTAIN_HUD_STATE_WORLDMAP   5
#define IM_ICE_MOUNTAIN_HUD_STATE_HIDDEN     6
#define IM_ICE_MOUNTAIN_MAP_DIRECTORY        0x17
#define IM_ICE_MOUNTAIN_EXIT_MAP             0x1A
#define IM_ICE_MOUNTAIN_SEQUENCE_EVENT_ID    2
#define IM_ICE_MOUNTAIN_SEQUENCE_LATCH_MASK  1
#define IM_ICE_MOUNTAIN_MUSIC_LATCH_MASK     8
#define IM_ICE_MOUNTAIN_WARNING_TEXT_ID      0x351
#define IM_ICE_MOUNTAIN_WARNING_DURATION     300.0f
#define IM_ICE_MOUNTAIN_GAME_BIT_RESET_COUNT 13

#define IM_ICE_MOUNTAIN_ENVFX_A 0xA3
#define IM_ICE_MOUNTAIN_ENVFX_B 0x9E
#define IM_ICE_MOUNTAIN_ENVFX_C 0x119
#define IM_ICE_MOUNTAIN_ENVFX_D 0x104

void IMIceMountain_enterWorldMap(GameObject* obj) {
    IMIceMountainState* state = obj->extra;
    s32 playerMode;
    GameObject* player;

    mainSetBits(GAMEBIT_IM_BikeRelated03A3, 0);
    mainSetBits(GAMEBIT_IM_BikeRelated03A2, 0);
    player = playerGetFocusObject(Obj_GetPlayerObject());
    if (player != NULL) {
        playerMode = VEHICLE_INTERFACE(player)->getRacePosition(player);
    } else {
        playerMode = 0;
    }
    lockLevel(mapGetDirIdx(IM_ICE_MOUNTAIN_MAP_DIRECTORY), 1);
    if (playerMode == IM_ICE_MOUNTAIN_PLAYER_MODE_WORLDMAP) {
        (*gGameUIInterface)->setCMenuShouldClose(1);
        state->eventState = IM_ICE_MOUNTAIN_HUD_STATE_WORLDMAP;
        mainSetBits(GAMEBIT_IMRelated037B, 1);
    } else {
        state->eventState = IM_ICE_MOUNTAIN_HUD_STATE_HIDDEN;
        mainSetBits(GAMEBIT_IMRelated00CE, 1);
    }
    mainSetBits(GAMEBIT_IM_BikeRelated0378, 0);
    mainSetBits(GAMEBIT_IM_BikeRelated03B9, 0);
}

void IMIceMountain_exitWorldMap(GameObject* obj, IMIceMountainState* state) {
    s32 playerMode;
    GameObject* player;

    (*gGameUIInterface)->setCMenuShouldClose(0);
    if (mainGetBit(GAMEBIT_IM_BikeRelated03A3) != 0) {
        mainSetBits(GAMEBIT_IM_BikeRelated03A3, 0);
        mainSetBits(GAMEBIT_IM_BikeRelated03A2, 0);
        mainSetBits(GAMEBIT_IM_BikeRelated0378, 0);
        mainSetBits(GAMEBIT_IM_BikeRelated03B9, 0);
        player = playerGetFocusObject(Obj_GetPlayerObject());
        if (player != NULL) {
            playerMode = VEHICLE_INTERFACE(player)->getRacePosition(player);
        } else {
            playerMode = 0;
        }
        mainSetBits(GAMEBIT_TrickyWarpEnabled, 1);
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 1, 1);
        if (playerMode == IM_ICE_MOUNTAIN_PLAYER_MODE_WORLDMAP) {
            (*gGameUIInterface)->setCMenuShouldClose(1);
            state->eventState = IM_ICE_MOUNTAIN_HUD_STATE_WORLDMAP;
            mainSetBits(GAMEBIT_IM_BikeRelated0379, 1);
        } else {
            state->eventState = IM_ICE_MOUNTAIN_HUD_STATE_HIDDEN;
            mainSetBits(0xcb, 1);
        }
    }
}

ObjectDescriptor gIMIceMountainObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)IMIceMountain_init,
    (ObjectDescriptorCallback)IMIceMountain_update,
    (ObjectDescriptorCallback)IMIceMountain_hitDetect,
    (ObjectDescriptorCallback)IMIceMountain_render,
    (ObjectDescriptorCallback)IMIceMountain_free,
    (ObjectDescriptorCallback)IMIceMountain_getObjectTypeId,
    IMIceMountain_getExtraSize,
};

void IMIceMountain_updateEventState(GameObject* obj) {
    IMIceMountainState* state = obj->extra;

    switch (state->eventState) {
    case 7:
        if (mainGetBit(GAMEBIT_IM_TrickyRelated006E) != 0) {
            state->eventState = 1;
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 2, 0);
        }
        break;
    case 1:
        if (mainGetBit(GAMEBIT_IM_CannonGuy1Dead) != 0 && mainGetBit(GAMEBIT_IM_CannonGuy2Dead) != 0) {
            mainSetBits(GAMEBIT_IM_SwitchVisible, 1);
            state->eventState = 2;
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0xb, 1);
        } else if (mainGetBit(GAMEBIT_IM_RescuedTricky) != 0) {
            state->eventState = 2;
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0xb, 1);
        }
        break;
    case 2:
        if (mainGetBit(GAMEBIT_IM_RescuedTricky) != 0) {
            state->eventState = 3;
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 6, 1);
        }
        break;
    case 3:
        if (mainGetBit(GAMEBIT_IM_RaceStarted) != 0) {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0, 0);
        }
        if (mainGetBit(GAMEBIT_IM_BikeRelated03A2) != 0) {
            state->eventState = 4;
            mainSetBits(GAMEBIT_IM_DestroyedBox1, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox2, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox3, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox4, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox5, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox6, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox7, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox8, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox9, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox10, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox11, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox12, 1);
            mainSetBits(GAMEBIT_IM_DestroyedBox13, 1);
            mainSetBits(GAMEBIT_IM_BikeRelated0E6A, 1);
            mainSetBits(GAMEBIT_IM_BikeRelated0E6B, 1);
        }
        if (obj->userData1 == 0) {
            getEnvfxAct(obj, obj, IM_ICE_MOUNTAIN_ENVFX_A, 0);
            getEnvfxAct(obj, obj, IM_ICE_MOUNTAIN_ENVFX_B, 0);
            getEnvfxAct(obj, obj, IM_ICE_MOUNTAIN_ENVFX_C, 0);
            getLActions(obj, obj, 0x15b, 0, 0, 0);
            getLActions(obj, obj, 0x15c, 0, 0, 0);
            getLActions(obj, obj, 0x17c, 0, 0, 0);
            getLActions(obj, obj, 0x17b, 0, 0, 0);
            (*gCloudActionInterface)->func09Nop(1);
            obj->userData1 = 1;
        }
        break;
    case 4:
        IMIceMountain_exitWorldMap(obj, state);
        break;
    case 5:
        if ((state->gameBitLatch.activeMask & IM_ICE_MOUNTAIN_SEQUENCE_LATCH_MASK) != 0) {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 3, 0);
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 4, 0);
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 6, 0);
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 7, 0);
            state->eventState = 0;
            (*gMapEventInterface)->setMapAct(obj->anim.mapEventSlot, 2);
        }
        break;
    case 6:
        if ((state->gameBitLatch.activeMask & IM_ICE_MOUNTAIN_SEQUENCE_LATCH_MASK) != 0) {
            state->warpCountdown = 2;
        }
        if (state->warpCountdown > 0) {
            if (--state->warpCountdown == 0) {
                mainSetBits(GAMEBIT_TrickyWarpEnabled, 0);
                warpToMap(IM_ICE_MOUNTAIN_EXIT_MAP, 0);
            }
        }
        break;
    }
}

int IMIceMountain_sequenceCallback(GameObject* obj, int unused, const ObjSeqState* animUpdate) {
    IMIceMountainState* state = obj->extra;
    int i;

    state->gameBitLatch.activeMask |= IM_ICE_MOUNTAIN_SEQUENCE_LATCH_MASK;
    for (i = 0; i < animUpdate->eventCount; i++) {
        if (animUpdate->eventIds[i] == IM_ICE_MOUNTAIN_SEQUENCE_EVENT_ID) {
            mainSetBits(GAMEBIT_IM_BikeRelated0378, 0);
            mainSetBits(GAMEBIT_IM_BikeRelated03B9, 0);
        }
    }
    return 0;
}

int IMIceMountain_getExtraSize(void) {
    return sizeof(IMIceMountainState);
}

int IMIceMountain_getObjectTypeId(void) {
    return 0;
}

void IMIceMountain_free(void) {
}

void IMIceMountain_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 v = visible;

    if (v != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void IMIceMountain_hitDetect(void) {
}

void IMIceMountain_update(GameObject* obj) {
    IMIceMountainState* state = obj->extra;

    if (obj->userData1 == 0) {
        getEnvfxAct(obj, obj, IM_ICE_MOUNTAIN_ENVFX_A, 0);
        getEnvfxAct(obj, obj, IM_ICE_MOUNTAIN_ENVFX_B, 0);
        getEnvfxAct(obj, obj, IM_ICE_MOUNTAIN_ENVFX_D, 0);
        (*gCloudActionInterface)->func09Nop(1);
        obj->userData1 = 1;
    }
    switch (state->mapAct) {
    case 1:
        IMIceMountain_updateEventState(obj);
        break;
    case 2:
        if (mainGetBit(GAMEBIT_IM_BikeRelated03A3) != 0) {
            IMIceMountain_enterWorldMap(obj);
        }
        break;
    case 3:
    case 4:
        break;
    }
    state->gameBitLatch.activeMask &= ~IM_ICE_MOUNTAIN_SEQUENCE_LATCH_MASK;
    if (state->warningTextTimer > 0.0f) {
        gameTextSetColor(0xFF, 0xFF, 0xFF, 0xFF);
        gameTextShow(IM_ICE_MOUNTAIN_WARNING_TEXT_ID);
        state->warningTextTimer -= timeDelta;
        if (state->warningTextTimer < 0.0f) {
            state->warningTextTimer = 0.0f;
        }
    }
    if ((*gSkyInterface)->getSunPosition(NULL) != 0) {
        if (state->musicTrack != -1) {
            state->musicTrack = -1;
            if ((state->gameBitLatch.activeMask & IM_ICE_MOUNTAIN_MUSIC_LATCH_MASK) != 0) {
                Music_Trigger(MUSICTRIG_galleon_docks, 0);
            }
        }
    } else {
        if (state->musicTrack != MUSICTRIG_galleon_docks) {
            state->musicTrack = MUSICTRIG_galleon_docks;
            if ((state->gameBitLatch.activeMask & IM_ICE_MOUNTAIN_MUSIC_LATCH_MASK) != 0) {
                Music_Trigger(MUSICTRIG_galleon_docks, 1);
            }
        }
    }
    GameBitLatch_Update(&state->gameBitLatch, 2, GAMEBIT_IM_TrickyRelated02C1, 568, GAMEBIT_IM_TrickyRelated01ED,
                          178);
    GameBitLatch_Update(&state->gameBitLatch, 16, 442, GAMEBIT_IM_TrickyRelated01B9, GAMEBIT_IM_TrickyRelated01D6,
                          180);
    GameBitLatch_Update(&state->gameBitLatch, 4, -1, -1, GAMEBIT_IM_WaterRelated03A0, 233);
    GameBitLatch_Update(&state->gameBitLatch, IM_ICE_MOUNTAIN_MUSIC_LATCH_MASK, -1, -1, GAMEBIT_IM_Done,
                          state->musicTrack);
}

void IMIceMountain_init(GameObject* obj) {
    IMIceMountainState* state = obj->extra;
    u8 i;

    obj->animEventCallback = IMIceMountain_sequenceCallback;
    for (i = 1; i <= IM_ICE_MOUNTAIN_GAME_BIT_RESET_COUNT; i++) {
        taskHintRecordCompletedTask(i);
    }
    state->warningTextTimer = IM_ICE_MOUNTAIN_WARNING_DURATION;
    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 1, 0);
    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 5, 1);
    unlockLevel(0, 0, 1);
    if (mainGetBit(GAMEBIT_IM_BikeRelated0379) != 0) {
        (*gMapEventInterface)->setMapAct(obj->anim.mapEventSlot, 2);
    }
    state->mapAct = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    switch (state->mapAct) {
    case 1:
        if (mainGetBit(GAMEBIT_IM_RaceStarted) != 0) {
            if (mainGetBit(GAMEBIT_IM_BikeRelated0379) != 0) {
                state->eventState = 5;
            } else {
                mainSetBits(GAMEBIT_IM_BikeRelated03A3, 0);
                mainSetBits(GAMEBIT_IM_BikeRelated03A2, 0);
                mainSetBits(0xcb, 0);
                mainSetBits(GAMEBIT_IM_BikeRelated0379, 0);
                state->eventState = 3;
            }
        } else {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0, 1);
            if (mainGetBit(GAMEBIT_IM_CannonGuy1Dead) != 0 && mainGetBit(GAMEBIT_IM_CannonGuy2Dead) != 0) {
                (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0xb, 1);
            }
            if (mainGetBit(GAMEBIT_IM_TrickyRelated006E) != 0) {
                state->eventState = 1;
            } else {
                (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 2, 1);
                state->eventState = 7;
            }
        }
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 3, 1);
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 4, 1);
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 7, 1);
        break;
    case 2:
        mainSetBits(GAMEBIT_IM_BikeRelated03A3, 0);
        mainSetBits(GAMEBIT_IM_BikeRelated03A2, 0);
        mainSetBits(GAMEBIT_IMRelated00CE, 0);
        mainSetBits(GAMEBIT_IMRelated037B, 0);
        mainSetBits(GAMEBIT_IM_OnBike, 0);
        mainSetBits(0x374, 0);
        mainSetBits(0x37c, 0);
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 2, 0);
        break;
    case 3:
    case 4:
        break;
    }
}
