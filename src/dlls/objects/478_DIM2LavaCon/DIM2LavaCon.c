/*
 * DIM2LavaCon (DLL 0x1DE) controls the area's heat shimmer, environment
 * effects, game-bit latches, and music transitions.
 */

#include "dlls/objects/478_DIM2LavaCon.h"

#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/dll_0011_screens.h"
#include "main/dll/player_objects.h"
#include "main/dll/savegame_load_api.h"
#include "main/gamebit_ids.h"
#include "main/object_render.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/sky_api.h"
#include "sys/objects.h"

#define DIM2_LAVA_CONTROL_ENVFX_A 0x163
#define DIM2_LAVA_CONTROL_ENVFX_B 0x166
#define DIM2_LAVA_CONTROL_ENVFX_C 0x165
#define DIM2_LAVA_CONTROL_ENVFX_D 0x164

#define DIM2_LAVA_CONTROL_GAMEBIT_0ACD 0xACD
#define DIM2_LAVA_CONTROL_GAMEBIT_0CC3 0xCC3
#define DIM2_LAVA_CONTROL_GAMEBIT_0D99 0xD99
/* DIM2_GAMEBIT_AREA_MUSIC_ACTIVE is shared through the unit header. */
#define DIM2_LAVA_CONTROL_GAMEBIT_0F04 0xF04

#define DIM2_LAVA_CONTROL_GAMEBIT_PRELOAD_LAST_INDEX 0x2D

#define DIM2_LAVA_CONTROL_MUSIC_TRIGGER_02C 0x2C
#define DIM2_LAVA_CONTROL_MUSIC_TRIGGER_0DE 0xDE

#define DIM2_LAVA_CONTROL_STATE_FLAG_COUNTDOWN_COMPLETE 0x01

#define DIM2_LAVA_CONTROL_LATCH_MUSIC_0DE          0x01
#define DIM2_LAVA_CONTROL_LATCH_AREA_MUSIC         0x02
#define DIM2_LAVA_CONTROL_LATCH_SHRINE_MUSIC       0x04
#define DIM2_LAVA_CONTROL_LATCH_CITY_TOMBS_MUSIC   0x08
#define DIM2_LAVA_CONTROL_LATCH_MUSIC_02C_INVERTED 0x10

#define DIM2_LAVA_CONTROL_HEAT_ALPHA_RESET            0xC0
#define DIM2_LAVA_CONTROL_HEAT_TARGET_COMPLETE_INDEX  0
#define DIM2_LAVA_CONTROL_HEAT_TARGET_COUNTDOWN_INDEX 3

enum {
    DIM2_LAVA_CONTROL_PHASE_WAIT = 0,
    DIM2_LAVA_CONTROL_PHASE_TRIGGERED = 1
};

enum {
    DIM2_LAVA_CONTROL_ENVFX_UPDATE_NONE = 0,
    DIM2_LAVA_CONTROL_ENVFX_UPDATE_QUEUED = 1,
    DIM2_LAVA_CONTROL_ENVFX_UPDATE_IMMEDIATE = 2
};

u8 gDim2LavaHeatAlphaTargets[DIM2_LAVA_CONTROL_HEAT_ALPHA_TARGET_COUNT] = {0xFF, 0xCD, 0xB9, 0xAA, 0, 0, 0, 0};

STATIC_ASSERT(sizeof(gDim2LavaHeatAlphaTargets) == 0x08);

void dim2lavacontrol_tickCountdown(GameObject* obj) {
    Dim2LavaControlState* state = obj->extra;

    if (((s32)state->statusFlags & DIM2_LAVA_CONTROL_STATE_FLAG_COUNTDOWN_COMPLETE) == 0) {
        const Dim2LavaControlPlacementView* placement = (const Dim2LavaControlPlacementView*)obj->anim.placementData;

        if ((s32)state->countdown > 0) {
            state->countdown -= 1;
            if (state->countdown == 0) {
                state->statusFlags |= DIM2_LAVA_CONTROL_STATE_FLAG_COUNTDOWN_COMPLETE;
                mainSetBits(placement->completionGameBit, 1);
            }
        }
    }
}

int dim2lavacontrol_getExtraSize(void) {
    return sizeof(Dim2LavaControlState);
}

void dim2lavacontrol_free(void) {
    setHeatEffectParams(DIM2_LAVA_CONTROL_HEAT_ALPHA_RESET, 1.0f);
    Music_Trigger(MUSICTRIG_PU3_Adventure_c4, 0);
    Rcp_DisableHeatEffect();
}

void dim2lavacontrol_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dim2lavacontrol_update(GameObject* obj) {
    int alphaDelta;
    GameObject* heldObject;
    Dim2LavaControlState* state;

    if (obj->userData1 != DIM2_LAVA_CONTROL_ENVFX_UPDATE_NONE) {
        if (obj->userData1 == DIM2_LAVA_CONTROL_ENVFX_UPDATE_IMMEDIATE) {
            getEnvfxActImmediately(0, 0, DIM2_LAVA_CONTROL_ENVFX_A, 0);
            getEnvfxActImmediately(0, 0, DIM2_LAVA_CONTROL_ENVFX_B, 0);
            getEnvfxActImmediately(0, 0, DIM2_LAVA_CONTROL_ENVFX_C, 0);
            getEnvfxActImmediately(0, 0, DIM2_LAVA_CONTROL_ENVFX_D, 0);
        } else {
            getEnvfxAct(0, 0, DIM2_LAVA_CONTROL_ENVFX_A, 0);
            getEnvfxAct(0, 0, DIM2_LAVA_CONTROL_ENVFX_B, 0);
            getEnvfxAct(0, 0, DIM2_LAVA_CONTROL_ENVFX_C, 0);
            getEnvfxAct(0, 0, DIM2_LAVA_CONTROL_ENVFX_D, 0);
        }
        obj->userData1 = DIM2_LAVA_CONTROL_ENVFX_UPDATE_NONE;
    }

    state = obj->extra;
    switch (state->phase) {
    case DIM2_LAVA_CONTROL_PHASE_WAIT:
        if (mainGetBit(DIM2_LAVA_CONTROL_GAMEBIT_0ACD) != 0) {
            mainSetBits(DIM2_LAVA_CONTROL_GAMEBIT_0CC3, 1);
            state->phase = DIM2_LAVA_CONTROL_PHASE_TRIGGERED;
        }
        break;
    case DIM2_LAVA_CONTROL_PHASE_TRIGGERED:
        break;
    }

    alphaDelta = state->heatEffectAlpha - gDim2LavaHeatAlphaTargets[state->countdown];
    if (alphaDelta != 0) {
        if (alphaDelta > 0) {
            state->heatEffectAlpha -= 1;
        } else {
            state->heatEffectAlpha += 1;
        }
        setHeatEffectParams(state->heatEffectAlpha, 1.0f);
    }

    if (Player_GetHeldObject(Obj_GetPlayerObject(), &heldObject) != 0) {
        if ((state->musicLatch.activeMask & DIM2_LAVA_CONTROL_LATCH_AREA_MUSIC) &&
            state->musicTriggerId != MUSICTRIG_WLC_Puzzle_e0) {
            Music_Trigger(state->musicTriggerId, 0);
            state->musicTriggerId = MUSICTRIG_WLC_Puzzle_e0;
            Music_Trigger(MUSICTRIG_WLC_Puzzle_e0, 1);
        }
    } else {
        if ((state->musicLatch.activeMask & DIM2_LAVA_CONTROL_LATCH_AREA_MUSIC) &&
            state->musicTriggerId != MUSICTRIG_WLC_Chambers) {
            Music_Trigger(state->musicTriggerId, 0);
            state->musicTriggerId = MUSICTRIG_WLC_Chambers;
            Music_Trigger(MUSICTRIG_WLC_Chambers, 1);
        }
    }

    GameBitLatch_Update(&state->musicLatch, DIM2_LAVA_CONTROL_LATCH_MUSIC_0DE, -1, -1, DIM2_LAVA_CONTROL_GAMEBIT_0D99,
                        DIM2_LAVA_CONTROL_MUSIC_TRIGGER_0DE);
    GameBitLatch_Update(&state->musicLatch, DIM2_LAVA_CONTROL_LATCH_AREA_MUSIC, -1, -1, DIM2_GAMEBIT_AREA_MUSIC_ACTIVE,
                        state->musicTriggerId);
    GameBitLatch_Update(&state->musicLatch, DIM2_LAVA_CONTROL_LATCH_CITY_TOMBS_MUSIC, -1, -1,
                        DIM2_LAVA_CONTROL_GAMEBIT_0F04, MUSICTRIG_citytombs);
    GameBitLatch_UpdateInverted(&state->musicLatch, DIM2_LAVA_CONTROL_LATCH_MUSIC_02C_INVERTED, -1, -1,
                                DIM2_LAVA_CONTROL_GAMEBIT_0F04, DIM2_LAVA_CONTROL_MUSIC_TRIGGER_02C);
    GameBitLatch_Update(&state->musicLatch, DIM2_LAVA_CONTROL_LATCH_SHRINE_MUSIC, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK,
                        MUSICTRIG_PU3_Adventure_c4);
}

void dim2lavacontrol_init(GameObject* obj, const Dim2LavaControlPlacementView* placement) {
    Dim2LavaControlState* state;
    u8 gameBitIndex;
    int gameBitState;

    if (getSaveGameLoadStatus() != 0) {
        obj->userData1 = DIM2_LAVA_CONTROL_ENVFX_UPDATE_IMMEDIATE;
    } else {
        obj->userData1 = DIM2_LAVA_CONTROL_ENVFX_UPDATE_QUEUED;
    }

    for (gameBitIndex = 1; gameBitIndex <= DIM2_LAVA_CONTROL_GAMEBIT_PRELOAD_LAST_INDEX; gameBitIndex++) {
        taskHintRecordCompletedTask(gameBitIndex);
    }

    state = obj->extra;
    state->countdown = (s8)placement->countdownInitialValue;
    state->savedCountdown = state->countdown;
    if (mainGetBit(placement->completionGameBit) != 0) {
        gameBitState = DIM2_LAVA_CONTROL_STATE_FLAG_COUNTDOWN_COMPLETE;
    } else {
        gameBitState = 0;
    }

    state->statusFlags |= gameBitState;
    state->musicTriggerId = MUSICTRIG_WLC_Chambers;
    state->phase = DIM2_LAVA_CONTROL_PHASE_WAIT;
    if ((state->statusFlags & DIM2_LAVA_CONTROL_STATE_FLAG_COUNTDOWN_COMPLETE) != 0) {
        state->countdown = DIM2_LAVA_CONTROL_HEAT_TARGET_COMPLETE_INDEX;
        state->heatEffectAlpha = gDim2LavaHeatAlphaTargets[DIM2_LAVA_CONTROL_HEAT_TARGET_COMPLETE_INDEX];
        setHeatEffectParams(gDim2LavaHeatAlphaTargets[DIM2_LAVA_CONTROL_HEAT_TARGET_COMPLETE_INDEX], 1.0f);
    } else {
        state->countdown = DIM2_LAVA_CONTROL_HEAT_TARGET_COUNTDOWN_INDEX;
        state->heatEffectAlpha = gDim2LavaHeatAlphaTargets[DIM2_LAVA_CONTROL_HEAT_TARGET_COUNTDOWN_INDEX];
        setHeatEffectParams(gDim2LavaHeatAlphaTargets[DIM2_LAVA_CONTROL_HEAT_TARGET_COUNTDOWN_INDEX], 1.0f);
    }

    Music_Trigger(MUSICTRIG_WLC_Corridors, 1);
    skySetEnvFxFlags(0);
}

Dim2LavaControlDescriptor gDIM2LavaControlObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        0,
        0,
        0,
        (ObjectDescriptorCallback)dim2lavacontrol_init,
        (ObjectDescriptorCallback)dim2lavacontrol_update,
        0,
        (ObjectDescriptorCallback)dim2lavacontrol_render,
        dim2lavacontrol_free,
        0,
        dim2lavacontrol_getExtraSize,
    },
    dim2lavacontrol_tickCountdown,
    0,
};
