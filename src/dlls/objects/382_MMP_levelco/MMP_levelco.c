/*
 * MMP_levelco (DLL 0x17E) - Moon Mountain Pass level controller.
 *
 * This singleton drives the area's environment, scripted music latches,
 * and the timed game-text display.
 */
#include "dlls/objects/382_MMP_levelco.h"

#include "dlls/objects/430_SH_LevelCon.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/savegame_load_api.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/gametext_show_api.h"
#include "main/lightmap_api.h"
#include "main/map_load.h"
#include "main/object_render.h"
#include "main/pi_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/sky_api.h"
#include "sys/objects.h"

#define MMP_LEVEL_CONTROL_ENVFX_ANIM_EVENT_1 0x13B
#define MMP_LEVEL_CONTROL_ENVFX_LOCAL_LAYER  0x138
#define MMP_LEVEL_CONTROL_ENVFX_COMMON       0x13A
#define MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_A_1  0x234
#define MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_A_2  0x235
#define MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_B_1  0x10C
#define MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_B_2  0x10D
#define MMP_LEVEL_CONTROL_ENVFX_MAP_CELL     0x139

#define MMP_LEVEL_CONTROL_GAMEBIT_ENVIRONMENT_A 0xD47
#define MMP_LEVEL_CONTROL_GAMEBIT_ENVIRONMENT_B 0xF33
#define MMP_LEVEL_CONTROL_GAMEBIT_MUSIC_LATCH_A 0x389

#define MMP_LEVEL_CONTROL_MAP_ID        0x12
#define MMP_LEVEL_CONTROL_SKY_GROUP     7
#define MMP_LEVEL_CONTROL_TEXT_ID       0x34F
#define MMP_LEVEL_CONTROL_TEXT_DURATION 300.0f

GameBitLatchState gMMPLevelControlMusicLatch;
f32 gMMPLevelControlTextCountdown;

int mmpLevelControl_processAnimEvents(GameObject* obj, int unusedArg2, ObjSeqState* animUpdate) {
    GameObject* player;
    int i;

    player = Obj_GetPlayerObject();
    animUpdate->movementState = 0;
    for (i = 0; i < animUpdate->eventCount; i++) {
        u8 eventId = animUpdate->eventIds[i];

        switch (eventId) {
        case 1:
            getEnvfxAct(obj, player, MMP_LEVEL_CONTROL_ENVFX_ANIM_EVENT_1, 0);
            break;
        case 2:
            getEnvfxAct(obj, player, MMP_LEVEL_CONTROL_ENVFX_LOCAL_LAYER, 0);
            break;
        }
    }
    mmpLevelControl_update(obj);
    return 0;
}

int mmpLevelControl_getExtraSize(void) {
    return 0;
}

int mmpLevelControl_getObjectTypeId(void) {
    return 0;
}

void mmpLevelControl_free(GameObject* obj) {
    gMMPLevelControlTextCountdown = 0.0f;
    gMMPLevelControlMusicLatch.activeMask = 0;
    Music_Trigger(MUSICTRIG_WLC_Puzzle, 0);
}

void mmpLevelControl_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void mmpLevelControl_hitDetect(void) {
}

void mmpLevelControl_update(GameObject* obj) {
    GameObject* playerForMap;
    GameObject* playerForFx;

    playerForMap = Obj_GetPlayerObject();
    playerForFx = Obj_GetPlayerObject();

    if (gMMPLevelControlTextCountdown > 0.0f) {
        gameTextShow(MMP_LEVEL_CONTROL_TEXT_ID);
        {
            f32 countdown = gMMPLevelControlTextCountdown - timeDelta;
            gMMPLevelControlTextCountdown = countdown;
            if (countdown < 0.0f) {
                gMMPLevelControlTextCountdown = 0.0f;
            }
        }
    }

    if (obj->userData1 != 0) {
        skySetEnvFxFlags(0);
        if (mainGetBit(MMP_LEVEL_CONTROL_GAMEBIT_ENVIRONMENT_A) != 0) {
            skySetSlotFlag80(MMP_LEVEL_CONTROL_SKY_GROUP, 1);
            if (obj->userData1 == 2) {
                getEnvfxActImmediately(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_COMMON, 0);
                getEnvfxActImmediately(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_A_1, 0);
                getEnvfxActImmediately(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_A_2, 0);
            } else {
                getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_COMMON, 0);
                getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_A_1, 0);
                getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_A_2, 0);
            }
            obj->userData2 = 0;
        } else if (mainGetBit(MMP_LEVEL_CONTROL_GAMEBIT_ENVIRONMENT_B) != 0) {
            skySetSlotFlag80(MMP_LEVEL_CONTROL_SKY_GROUP, 1);
            if (obj->userData1 == 2) {
                getEnvfxActImmediately(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_COMMON, 0);
                getEnvfxActImmediately(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_B_1, 0);
                getEnvfxActImmediately(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_B_2, 0);
            } else {
                getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_COMMON, 0);
                getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_B_1, 0);
                getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_B_2, 0);
            }
            obj->userData2 = 1;
        } else if (coordsToMapCell(playerForMap->anim.localPosX, playerForMap->anim.localPosZ) ==
                   MMP_LEVEL_CONTROL_MAP_ID) {
            skySetSlotFlag80(MMP_LEVEL_CONTROL_SKY_GROUP, 0);
            if (obj->userData1 == 2) {
                getEnvfxActImmediately(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_COMMON, 0);
                getEnvfxActImmediately(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_LOCAL_LAYER, 0);
                getEnvfxActImmediately(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_MAP_CELL, 0);
            } else {
                getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_COMMON, 0);
                getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_LOCAL_LAYER, 0);
                getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_MAP_CELL, 0);
            }
            obj->userData2 = 0;
        }
        Music_Trigger(MUSICTRIG_Barrels, 1);
        obj->userData1 = 0;
    }

    if (obj->userData2 != 0 && mainGetBit(MMP_LEVEL_CONTROL_GAMEBIT_ENVIRONMENT_B) == 0) {
        skySetSlotFlag80(MMP_LEVEL_CONTROL_SKY_GROUP, 0);
        getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_COMMON, 0);
        getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_LOCAL_LAYER, 0);
        getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_MAP_CELL, 0);
        obj->userData2 = 0;
    } else if (obj->userData2 == 0 && mainGetBit(MMP_LEVEL_CONTROL_GAMEBIT_ENVIRONMENT_B) != 0) {
        skySetSlotFlag80(MMP_LEVEL_CONTROL_SKY_GROUP, 1);
        getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_COMMON, 0);
        getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_B_1, 0);
        getEnvfxAct(obj, playerForFx, MMP_LEVEL_CONTROL_ENVFX_GAMEBIT_B_2, 0);
        obj->userData2 = 1;
    }

    GameBitLatch_Update(&gMMPLevelControlMusicLatch, 1, -1, -1, MMP_LEVEL_CONTROL_GAMEBIT_MUSIC_LATCH_A,
                          MUSICTRIG_WLC_Puzzle);
    GameBitLatch_Update(&gMMPLevelControlMusicLatch, 2, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK,
                          MUSICTRIG_PU3_Adventure_c4);
}

void mmpLevelControl_init(GameObject* obj) {
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    if (getSaveGameLoadStatus() != 0) {
        obj->userData1 = 2;
    } else {
        obj->userData1 = 1;
    }
    obj->userData2 = mainGetBit(MMP_LEVEL_CONTROL_GAMEBIT_ENVIRONMENT_B);
    obj->animEventCallback = mmpLevelControl_processAnimEvents;
    unlockLevel(mapGetDirIdx(MMP_LEVEL_CONTROL_MAP_ID), 0, 0);
    gMMPLevelControlTextCountdown = MMP_LEVEL_CONTROL_TEXT_DURATION;
    gMMPLevelControlMusicLatch.activeMask = 0;
    Music_Trigger(MUSICTRIG_wind_ambi, 0);
    Music_Trigger(MUSICTRIG_mammoth_walk_db, 0);
    Music_Trigger(MUSICTRIG_LVF_Tracking_f2, 0);
    Music_Trigger(MUSICTRIG_CRF_Swim, 0);
    Music_Trigger(MUSICTRIG_cldrnr_walkabout, 0);
    mainSetBits(GAMEBIT_VFP_MusicLatch, 0);
}

void mmpLevelControl_release(void) {
}

void mmpLevelControl_initialise(void) {
}

ObjectDescriptor gMMPLevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmpLevelControl_initialise,
    (ObjectDescriptorCallback)mmpLevelControl_release,
    0,
    (ObjectDescriptorCallback)mmpLevelControl_init,
    (ObjectDescriptorCallback)mmpLevelControl_update,
    (ObjectDescriptorCallback)mmpLevelControl_hitDetect,
    (ObjectDescriptorCallback)mmpLevelControl_render,
    (ObjectDescriptorCallback)mmpLevelControl_free,
    (ObjectDescriptorCallback)mmpLevelControl_getObjectTypeId,
    mmpLevelControl_getExtraSize,
};
