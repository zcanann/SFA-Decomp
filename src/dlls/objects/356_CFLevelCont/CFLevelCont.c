/* CloudRunner Fortress level controller. */

#include "dlls/objects/274.h"
#include "dlls/objects/356_CFLevelCont.h"

#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/player_api.h"
#include "main/dll/player_staff_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/maketex_timer_api.h"
#include "main/mapEvent.h"
#include "main/mapEventTypes.h"
#include "main/map_load.h"
#include "main/object_render.h"
#include "main/pi_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/shader_api.h"
#include "main/sky_api.h"
#include "sys/objects.h"

#define CFLEVELCONTROL_EXIT_EVENT_ID    1
#define CFLEVELCONTROL_EXIT_MAP_ID      0x2B
#define CFLEVELCONTROL_MAP_EVENT_ID     0x1D
#define CFLEVELCONTROL_CELL_CAMERA_MODE 0x47
#define CFLEVELCONTROL_OBJECT_SLOT      0x51
#define CFLEVELCONTROL_SPECIAL_MAP_ID   0x2CEF
#define CFLEVELCONTROL_ENVFX_PRIMARY    0x56
#define CFLEVELCONTROL_ENVFX_SHARED     0x0D
#define CFLEVELCONTROL_ENVFX_DAY_A      0x11
#define CFLEVELCONTROL_ENVFX_DAY_B      0x0E
#define CFLEVELCONTROL_ENVFX_NIGHT_A    0x7E
#define CFLEVELCONTROL_ENVFX_NIGHT_B    0x7D

s16 gCfLevelControlResetGameBits[CFLEVELCONTROL_RESET_GAME_BIT_TABLE_COUNT] = {
    GAMEBIT_CFRelated02FC, GAMEBIT_CFRelated02FD, GAMEBIT_CFRelated02FE, GAMEBIT_CFRelated02FF,
    GAMEBIT_CFRelated0B2A, GAMEBIT_CFRelated0B2B, GAMEBIT_CFRelated0B2C, GAMEBIT_CFRelated0B2D,
    GAMEBIT_CFRelated0B2E, GAMEBIT_CFRelated0B2F, GAMEBIT_CFRelated0B30, GAMEBIT_CFRelated0B31,
    GAMEBIT_CFRelated0B6C, GAMEBIT_CFRelated0B32, GAMEBIT_CFRelated0B37, GAMEBIT_CFRelated0B38,
    GAMEBIT_CFRelated0B39, GAMEBIT_CFRelated0B3A, GAMEBIT_CFRelated0B3B, GAMEBIT_CFRelated0B3C,
    GAMEBIT_CFRelated0B3D, GAMEBIT_CFRelated0B3E, GAMEBIT_CFRelated0B3F, 0,
};
const CfLevelControlRestartPoint gCfLevelControlRestartPoint = {
    {746.81787109375f, 1309.0f, -16378.33984375f},
    0.0f,
};
int cflevelcontrol_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int eventIndex;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        int eventId = animUpdate->eventIds[eventIndex];
        switch (eventId) {
        case CFLEVELCONTROL_EXIT_EVENT_ID:
            mainSetBits(GAMEBIT_CFRaceRelated0DCB, 1);
            mainSetBits(GAMEBIT_CF_ObjGroups2, 0);
            loadMapAndParent(CFLEVELCONTROL_EXIT_MAP_ID);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(CFLEVELCONTROL_EXIT_MAP_ID), 0);
            break;
        }
    }
    return 0;
}

int cflevelcontrol_getExtraSize(void) {
    return sizeof(CfLevelControlState);
}

int cflevelcontrol_getObjectTypeId(void) {
    return 0;
}

void cflevelcontrol_free(GameObject* obj) {
}

void cflevelcontrol_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    s32 v = visible;
    if (v != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void cflevelcontrol_hitDetect(void) {
}

void cflevelcontrol_update(GameObject* obj) {
    CfLevelControlState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();
    Vec3f restartPosition;
    u32 lever974Set;
    u8 lever975Set;
    int hasStaff;
    int cameraMode;

    restartPosition = gCfLevelControlRestartPoint.position;

    if (state->flags.runObjectLoadCallbacks) {
        objCallOnLoadCallback(ObjList_FindObjectById(0x47FAE));
        objCallOnLoadCallback(ObjList_FindObjectById(0x47F83));
        objCallOnLoadCallback(ObjList_FindObjectById(0x47F8F));
        objCallOnLoadCallback(ObjList_FindObjectById(0x47FA2));
        objCallOnLoadCallback(ObjList_FindObjectById(0x29F2));
        objCallOnLoadCallback(ObjList_FindObjectById(0x29F3));
        objCallOnLoadCallback(ObjList_FindObjectById(0x29EF));
        objCallOnLoadCallback(ObjList_FindObjectById(0x29EE));
        state->flags.runObjectLoadCallbacks = 0;
    }

    if ((*gMapEventInterface)->getMapAct(CFLEVELCONTROL_MAP_EVENT_ID) == 1 &&
        mainGetBit(GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE) != 0) {
        (*gMapEventInterface)->setMapAct(CFLEVELCONTROL_MAP_EVENT_ID, 2);
    }

    lever974Set = (u8)mainGetBit(GAMEBIT_CFLever0974);
    lever975Set = mainGetBit(GAMEBIT_CFLever0975);
    if (state->flags.lever974WasSet == 0 || state->flags.lever975WasSet == 0) {
        if (state->flags.lever974WasSet == 0 && state->flags.lever975WasSet == 0) {
            if (lever974Set != 0 || lever975Set != 0) {
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
        } else if (lever974Set != 0 && lever975Set != 0) {
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
        }
    }

    state->flags.lever974WasSet = lever974Set;
    state->flags.lever975WasSet = lever975Set;

    if (obj->userData1 == 0) {
        getEnvfxActImmediately(obj, obj, CFLEVELCONTROL_ENVFX_PRIMARY, 0);
        if (mainGetBit(GAMEBIT_CFRelated0D73) == 0) {
            getEnvfxActImmediately(obj, obj, CFLEVELCONTROL_ENVFX_SHARED, 0);
            getEnvfxActImmediately(obj, obj, CFLEVELCONTROL_ENVFX_DAY_A, 0);
            getEnvfxActImmediately(obj, obj, CFLEVELCONTROL_ENVFX_DAY_B, 0);
            skySetLightIndex(0, 0.0f);
            mainSetBits(GAMEBIT_CFRelated0D73, 1);
        }

        if (mainGetBit(GAMEBIT_CFRelated0DCA) != 0) {
            getEnvfxActImmediately(obj, obj, CFLEVELCONTROL_ENVFX_SHARED, 0);
            getEnvfxActImmediately(obj, obj, CFLEVELCONTROL_ENVFX_NIGHT_A, 0);
            getEnvfxActImmediately(obj, obj, CFLEVELCONTROL_ENVFX_NIGHT_B, 0);
            skySetLightIndex(1, 0.0f);
            mainSetBits(GAMEBIT_CFRelated0DCA, 0);
            unlockLevel(0, 0, 1);
        }

        obj->userData1 = 1;
    }

    if (mainGetBit(GAMEBIT_CF_NotRecoveredStaff) != 0 && (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
        mainSetBits(GAMEBIT_CF_HaveStaff, 0);
    }

    hasStaff = mainGetBit(GAMEBIT_CF_HaveStaff);
    if (hasStaff != 0 && playerIsDisguised(player) == 0) {
        staffToggle(Obj_GetPlayerObject(), 0);
    } else if (hasStaff == 0 && playerIsDisguised(player) == 0) {
        staffToggle(Obj_GetPlayerObject(), 1);
    }

    if (mainGetBit(GAMEBIT_CFRestartPointRelated0D3D) != 0) {
        (*gMapEventInterface)->restartPoint(&restartPosition, 0, getCurMapLayer(), 1);
        mainSetBits(GAMEBIT_CFRestartPointRelated0D3D, 0);
        getEnvfxActImmediately(obj, obj, CFLEVELCONTROL_ENVFX_SHARED, 0);
        getEnvfxActImmediately(obj, obj, CFLEVELCONTROL_ENVFX_DAY_A, 0);
        skySetLightIndex(1, 1.0f);
    }

    cameraMode = (*gCameraInterface)->getMode();
    switch (cameraMode) {
    case CFLEVELCONTROL_CELL_CAMERA_MODE:
        if (state->previousCameraMode != CFLEVELCONTROL_CELL_CAMERA_MODE) {
            mainSetBits(GAMEBIT_SH_Entered00C0, 1);
        }
        break;
    default:
        if (state->previousCameraMode == CFLEVELCONTROL_CELL_CAMERA_MODE) {
            mainSetBits(GAMEBIT_SH_WarpStoneRelated01A8, 1);
        }
        break;
    }
    state->previousCameraMode = (s8)(*gCameraInterface)->getMode();

    GameBitLatch_Update(&state->gameBitLatch, 4, -1, -1, GAMEBIT_CFRelated0983, 0xB0);
    GameBitLatch_Update(&state->gameBitLatch, 8, -1, -1, GAMEBIT_CFRelated0983, 0x38);
    GameBitLatch_UpdateInverted(&state->gameBitLatch, 0x100, -1, -1, GAMEBIT_CFRelated0983, 0x16);
    GameBitLatch_UpdateInverted(&state->gameBitLatch, 0x80, -1, -1, GAMEBIT_CFRelated0983, 0x39);

    if (mainGetBit(GAMEBIT_CFRelated0983) == 0) {
        if (mainGetBit(GAMEBIT_CFRelated0E23) == 0) {
            GameBitLatch_UpdateInverted(&state->gameBitLatch, 0x200, -1, -1, GAMEBIT_CFRelated0984, 0xAD);
            GameBitLatch_Update(&state->gameBitLatch, 0x40, -1, -1, GAMEBIT_CFRelated0984, 0x16);
        }
        if (mainGetBit(GAMEBIT_CFRelated0984) != 0) {
            GameBitLatch_Update(&state->gameBitLatch, 0x20, -1, -1, GAMEBIT_CFRelated0E23, 0x17);
            GameBitLatch_UpdateInverted(&state->gameBitLatch, 0x400, -1, -1, GAMEBIT_CFRelated0E23, 0x16);
        }
    }

    GameBitLatch_Update(&state->gameBitLatch, 1, GAMEBIT_SH_WarpStoneRelated01A8, GAMEBIT_SH_Entered00C0,
                          GAMEBIT_CFRelated0DB8, 0xAE);
    GameBitLatch_Update(&state->gameBitLatch, 0x10, -1, -1, GAMEBIT_CFRelated0E1D, 0x36);
    GameBitLatch_Update(&state->gameBitLatch, 0x1000, -1, -1, GAMEBIT_CFRelated0E1D, 0xF1);
    GameBitLatch_Update(&state->gameBitLatch, 2, -1, -1, GAMEBIT_CFRelated0B46, 0xAF);
    GameBitLatch_Update(&state->gameBitLatch, 0x800, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK,
                        MUSICTRIG_PU3_Adventure_c4);
}

void cflevelcontrol_init(GameObject* obj, CfLevelControlPlacement* unusedPlacement) {
    CfLevelControlState* state;
    int gameBitIndex;

    state = obj->extra;
    state->gameBitLatch.activeMask = 0;
    state->previousCameraMode = -1;
    storeZeroToFloatParam(&state->timer);
    s16toFloat(&state->timer, 0x1E0);
    state->flags.unknown40 = 0;
    obj->animEventCallback = cflevelcontrol_sequenceCallback;
    mainSetBits(GAMEBIT_CFRelated0983,
                ((CfLevelControlPlacement*)obj->anim.placementData)->base.ident != CFLEVELCONTROL_SPECIAL_MAP_ID);
    if (mainGetBit(GAMEBIT_CFRelated02FE) == 0) {
        for (gameBitIndex = 0; gameBitIndex < CFLEVELCONTROL_RESET_GAME_BIT_COUNT; gameBitIndex++) {
            mainSetBits(gCfLevelControlResetGameBits[gameBitIndex], 0);
        }
    }
    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 4, 0);
    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0x11, 0);
    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0x15, 0);
    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0x16, 0);
    state->flags.lever974WasSet = mainGetBit(GAMEBIT_CFLever0974);
    state->flags.lever975WasSet = mainGetBit(GAMEBIT_CFLever0975);
    objSetSlot(obj, CFLEVELCONTROL_OBJECT_SLOT);
    state->flags.runObjectLoadCallbacks = 1;
}

void cflevelcontrol_release(void) {
}

void cflevelcontrol_initialise(void) {
}

ObjectDescriptor gCFLevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cflevelcontrol_initialise,
    (ObjectDescriptorCallback)cflevelcontrol_release,
    0,
    (ObjectDescriptorCallback)cflevelcontrol_init,
    (ObjectDescriptorCallback)cflevelcontrol_update,
    (ObjectDescriptorCallback)cflevelcontrol_hitDetect,
    (ObjectDescriptorCallback)cflevelcontrol_render,
    (ObjectDescriptorCallback)cflevelcontrol_free,
    (ObjectDescriptorCallback)cflevelcontrol_getObjectTypeId,
    cflevelcontrol_getExtraSize,
};
