/*
 * DIM_LevelCo (DLL 0x1CD) - level-control object for Snowhorn Wastes 2.
 * Manages time-of-day music (day=0xC5, night=0xE2), map-event latching via
 * GameBitLatch_Update (8 latch bits controlling music triggers), environment
 * fx for the lava area, an NPC dialogue trigger (game bits 0x3E2/0x3E3), and
 * initial level unlock.
 */

#include "dlls/objects/461_DIM_LevelCo.h"

#include "dlls/objects/430_SH_LevelCon.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0011_screens.h"
#include "main/dll/savegame_load_api.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gametext_color_api.h"
#include "main/gametext_show_api.h"
#include "main/map_load.h"
#include "main/object_render.h"
#include "main/rcp_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/mapEventTypes.h"

#define DIM_LEVEL_CONTROL_GAMEBIT_D0B 0xD0B
#define DIM_LEVEL_CONTROL_GAMEBIT_D0C 0xD0C
#define DIM_LEVEL_CONTROL_GAMEBIT_D0D 0xD0D
#define DIM_LEVEL_CONTROL_GAMEBIT_D0E 0xD0E

#define DIM_LEVEL_CONTROL_GAMEBIT_0017 0x017
#define DIM_LEVEL_CONTROL_GAMEBIT_0EAD 0xEAD
#define DIM_LEVEL_CONTROL_GAMEBIT_089D 0x89D
#define DIM_LEVEL_CONTROL_GAMEBIT_08A4 0x8A4
#define DIM_LEVEL_CONTROL_GAMEBIT_08A5 0x8A5
#define DIM_LEVEL_CONTROL_GAMEBIT_0F0A 0xF0A

#define DIM_LEVEL_CONTROL_LATCH_GAMEBIT_01A7 0x1A7
#define DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0C1E 0xC1E
#define DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0C1F 0xC1F
#define DIM_LEVEL_CONTROL_LATCH_GAMEBIT_01BA 0x1BA
#define DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0C20 0xC20
#define DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0D8F 0xD8F

/* Env-effect IDs co-activated once on the lava-area replay; individual roles remain opaque. */
#define DIM_LEVEL_CONTROL_ENVFX_A 0x160
#define DIM_LEVEL_CONTROL_ENVFX_B 0x15A
#define DIM_LEVEL_CONTROL_ENVFX_C 0x15C
#define DIM_LEVEL_CONTROL_ENVFX_D 0x15F

#define DIM_LEVEL_CONTROL_MUSICTRIG_DAY   0xC5
#define DIM_LEVEL_CONTROL_MUSICTRIG_NIGHT 0xE2
#define DIM_LEVEL_CONTROL_MUSICTRIG_02B   0x2B
#define DIM_LEVEL_CONTROL_MUSICTRIG_035   0x35
#define DIM_LEVEL_CONTROL_MUSICTRIG_0CF   0xCF
#define DIM_LEVEL_CONTROL_MUSICTRIG_0DC   0xDC

#define DIM_LEVEL_CONTROL_MESSAGE_TEXT_ID          0x430
#define DIM_LEVEL_CONTROL_NPC_DIALOGUE_ID          0x4BA
#define DIM_LEVEL_CONTROL_NPC_DIALOGUE_SPEAKER     0x14
#define DIM_LEVEL_CONTROL_NPC_DIALOGUE_VOICE       0x8C
#define DIM_LEVEL_CONTROL_DINO_HORN_GROUP_MAP_ID   0x13
#define DIM_LEVEL_CONTROL_DINO_HORN_GROUP_ID       0x0D
#define DIM_LEVEL_CONTROL_INITIAL_DIALOGUE_GAMEBIT 0x0DC

int dim_levelcontrol_getExtraSize(void) {
    return sizeof(DimLevelControlState);
}

void dim_levelcontrol_free(GameObject* unused) {
    (void)unused;

    Music_Trigger(MUSICTRIG_drako_1, 0);
    Music_Trigger(MUSICTRIG_citytombs_ed, 0);
    Rcp_DisableHeatEffect();
}

void dim_levelcontrol_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                             s8 visible) {
    s32 isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dim_levelcontrol_update(GameObject* obj) {
    u8 gameBitD0B;
    u8 gameBitD0C;
    u8 gameBitD0D;
    u8 gameBitD0E;
    DimLevelControlState* state;
    u32 triggerLostInBlizzard;
    u32 lostInBlizzardState;

    gameBitD0B = mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_D0B);
    gameBitD0C = mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_D0C);
    gameBitD0D = mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_D0D);
    gameBitD0E = mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_D0E);
    state = obj->extra;
    if ((gameBitD0B && !state->statusGameBitD0B) || (gameBitD0C && !state->statusGameBitD0C) ||
        (gameBitD0D && !state->statusGameBitD0D) || (gameBitD0E && !state->statusGameBitD0E)) {
        Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
    }
    state->statusGameBitD0B = gameBitD0B;
    state->statusGameBitD0C = gameBitD0C;
    state->statusGameBitD0D = gameBitD0D;
    state->statusGameBitD0E = gameBitD0E;
    if (!state->cannonStatusGameBit && mainGetBit(GAMEBIT_DIM_CannonRelated0A21) != 0) {
        Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
        state->cannonStatusGameBit = 1;
    }
    if (obj->userData1 != 0) {
        if (mainGetBit(GAMEBIT_DIM_FlewTo) == 0 ||
            (mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_0017) != 0 && mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_0EAD) == 0)) {
            if (obj->userData1 == 2) {
                getEnvfxActImmediately(0, 0, DIM_LEVEL_CONTROL_ENVFX_A, 0);
                getEnvfxActImmediately(0, 0, DIM_LEVEL_CONTROL_ENVFX_B, 0);
                getEnvfxActImmediately(0, 0, DIM_LEVEL_CONTROL_ENVFX_C, 0);
                getEnvfxActImmediately(0, 0, DIM_LEVEL_CONTROL_ENVFX_D, 0);
            } else {
                getEnvfxAct(0, 0, DIM_LEVEL_CONTROL_ENVFX_A, 0);
                getEnvfxAct(0, 0, DIM_LEVEL_CONTROL_ENVFX_B, 0);
                getEnvfxAct(0, 0, DIM_LEVEL_CONTROL_ENVFX_C, 0);
                getEnvfxAct(0, 0, DIM_LEVEL_CONTROL_ENVFX_D, 0);
            }
        }
        obj->userData1 = 0;
    }
    if (state->dinoHornGroupEnabled != 0) {
        if (mainGetBit(GAMEBIT_ITEM_DinoHorn_651) == 0) {
            (*gMapEventInterface)
                ->setObjGroupStatus(DIM_LEVEL_CONTROL_DINO_HORN_GROUP_MAP_ID, DIM_LEVEL_CONTROL_DINO_HORN_GROUP_ID, 0);
            state->dinoHornGroupEnabled = 0;
        }
    } else {
        if (mainGetBit(GAMEBIT_ITEM_DinoHorn_651) != 0) {
            (*gMapEventInterface)
                ->setObjGroupStatus(DIM_LEVEL_CONTROL_DINO_HORN_GROUP_MAP_ID, DIM_LEVEL_CONTROL_DINO_HORN_GROUP_ID, 1);
            state->dinoHornGroupEnabled = 1;
        }
    }
    if (state->messageTimer > 0.0f) {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShow(DIM_LEVEL_CONTROL_MESSAGE_TEXT_ID);
        state->messageTimer -= timeDelta;
        if (state->messageTimer < 0.0f) {
            state->messageTimer = 0.0f;
        }
    }
    if (state->lostInBlizzardDialogueFired == 0) {
        triggerLostInBlizzard = mainGetBit(GAMEBIT_DIM_TriggerLostInBlizzard);
        lostInBlizzardState = mainGetBit(GAMEBIT_NW_SnowHorn03E3);
        state->lostInBlizzardDialogueFired = (u8)(lostInBlizzardState & triggerLostInBlizzard);
        if (state->lostInBlizzardDialogueFired != 0) {
            (*gGameUIInterface)
                ->showNpcDialogue(DIM_LEVEL_CONTROL_NPC_DIALOGUE_ID, DIM_LEVEL_CONTROL_NPC_DIALOGUE_SPEAKER,
                                  DIM_LEVEL_CONTROL_NPC_DIALOGUE_VOICE, 1);
        }
    }
    triggerLostInBlizzard = mainGetBit(GAMEBIT_DIM_TriggerLostInBlizzard);
    {
        int snowHornCondition = !mainGetBit(GAMEBIT_NW_SnowHorn03E3);
        triggerLostInBlizzard = snowHornCondition & triggerLostInBlizzard;
    }
    lostInBlizzardState = triggerLostInBlizzard & 0xff;
    if (lostInBlizzardState != state->lostInBlizzardState) {
        mainSetBits(GAMEBIT_DIM_LostInBlizzard, lostInBlizzardState);
        state->lostInBlizzardState = lostInBlizzardState;
    }
    if (!(u8)mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_08A5) && mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_089D) != 0) {
        mainSetBits(DIM_LEVEL_CONTROL_GAMEBIT_08A4, 1);
    }
    if ((*gSkyInterface)->getSunPosition(0) == 0) {
        if (state->dayNightMusicTrigger != DIM_LEVEL_CONTROL_MUSICTRIG_NIGHT) {
            state->dayNightMusicTrigger = DIM_LEVEL_CONTROL_MUSICTRIG_NIGHT;
            if (state->musicLatchMask & 4) {
                Music_Trigger(DIM_LEVEL_CONTROL_MUSICTRIG_DAY, 0);
                Music_Trigger(DIM_LEVEL_CONTROL_MUSICTRIG_NIGHT, 1);
            }
        }
    } else {
        if (state->dayNightMusicTrigger != DIM_LEVEL_CONTROL_MUSICTRIG_DAY) {
            state->dayNightMusicTrigger = DIM_LEVEL_CONTROL_MUSICTRIG_DAY;
            if (state->musicLatchMask & 4) {
                Music_Trigger(DIM_LEVEL_CONTROL_MUSICTRIG_NIGHT, 0);
                Music_Trigger(DIM_LEVEL_CONTROL_MUSICTRIG_DAY, 1);
            }
        }
    }
    GameBitLatch_Update((GameBitLatchState*)&state->musicLatchMask, 1, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_01A7,
                          GAMEBIT_SH_Landed064B, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0C1E, MUSICTRIG_drako_1);
    GameBitLatch_Update((GameBitLatchState*)&state->musicLatchMask, 2, GAMEBIT_SH_WarpStoneRelated01A8,
                          GAMEBIT_SH_Entered00C0, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0C1F,
                          DIM_LEVEL_CONTROL_MUSICTRIG_0CF);
    GameBitLatch_Update((GameBitLatchState*)&state->musicLatchMask, 4, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_01BA,
                          GAMEBIT_IM_TrickyRelated01B9, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0C20,
                          state->dayNightMusicTrigger);
    GameBitLatch_Update((GameBitLatchState*)&state->musicLatchMask, 8, -1, -1, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0D8F,
                          DIM_LEVEL_CONTROL_MUSICTRIG_0DC);
    GameBitLatch_Update((GameBitLatchState*)&state->musicLatchMask, 0x10, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_01A7,
                          GAMEBIT_SH_Landed064B, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0C1E, MUSICTRIG_citytombs_ed);
    GameBitLatch_Update((GameBitLatchState*)&state->musicLatchMask, 0x20, GAMEBIT_SH_WarpStoneRelated01A8,
                          GAMEBIT_SH_Entered00C0, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0C1F, MUSICTRIG_Teleport);
    GameBitLatch_Update((GameBitLatchState*)&state->musicLatchMask, 0x40, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_01BA,
                          GAMEBIT_IM_TrickyRelated01B9, DIM_LEVEL_CONTROL_LATCH_GAMEBIT_0C20,
                          DIM_LEVEL_CONTROL_MUSICTRIG_035);
    GameBitLatch_Update((GameBitLatchState*)&state->musicLatchMask, 0x100, -1, -1,
                          GAMEBIT_DIM_TriggerLostInBlizzard, DIM_LEVEL_CONTROL_MUSICTRIG_02B);
}

void dim_levelcontrol_init(GameObject* obj) {
    DimLevelControlState* state;
    u8 taskHintIndex;

    randomGetRange(0, 11);
    state = obj->extra;
    state->lostInBlizzardState = 0;
    state->messageTimer = 300.0f;
    if (getSaveGameLoadStatus() != 0) {
        obj->userData1 = 2;
    } else {
        obj->userData1 = 1;
    }
    for (taskHintIndex = 1; taskHintIndex <= 38; taskHintIndex++) {
        taskHintRecordCompletedTask(taskHintIndex);
    }
    state->lostInBlizzardDialogueFired = mainGetBit(DIM_LEVEL_CONTROL_INITIAL_DIALOGUE_GAMEBIT);
    mainSetBits(DIM_LEVEL_CONTROL_GAMEBIT_0F0A, 0);
    if (mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_089D) != 0 && mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_08A5) == 0) {
        mainSetBits(DIM_LEVEL_CONTROL_GAMEBIT_089D, 0);
    }
    state->statusGameBitD0B = mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_D0B);
    state->statusGameBitD0C = mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_D0C);
    state->statusGameBitD0D = mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_D0D);
    state->statusGameBitD0E = mainGetBit(DIM_LEVEL_CONTROL_GAMEBIT_D0E);
    state->cannonStatusGameBit = mainGetBit(GAMEBIT_DIM_CannonRelated0A21);
    (*gMapEventInterface)->setMapAct(obj->anim.mapEventSlot, 1);
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    unlockLevel(0, 0, 1);
}

ObjectDescriptor gDIM_LevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dim_levelcontrol_init,
    (ObjectDescriptorCallback)dim_levelcontrol_update,
    0,
    (ObjectDescriptorCallback)dim_levelcontrol_render,
    (ObjectDescriptorCallback)dim_levelcontrol_free,
    0,
    dim_levelcontrol_getExtraSize,
};
