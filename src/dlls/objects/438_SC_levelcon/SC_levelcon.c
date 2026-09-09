/*
 * SC_levelcon (DLL 0x1B6) - the LightFoot Village level controller.
 *
 * Coordinates the village map state, fog, music, challenge timers, and the
 * three-tree totem combination.
 */

#include "dlls/objects/438_SC_levelcon.h"

#include "dlls/objects/440_SC_totempol.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/savegame_load_api.h"
#include "main/frame_timing.h"
#include "main/game_timer_control_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/gametext_show_api.h"
#include "main/lightmap_api.h"
#include "main/map_load.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/screen_transition.h"
#include "main/sky_api.h"
#include "main/sky_interface.h"
#include "sys/objects.h"

u16 gScLevelControlTotemComboSequence[4] = {
    SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_1,
    SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_2,
    SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_3,
    0,
};

#define SC_LEVEL_CONTROL_ANIM_EVENT_FLAG_PROCESSED   0x01
#define SC_LEVEL_CONTROL_ANIM_EVENT_FLAG_3_TRIGGERED 0x02

#define SC_LEVEL_CONTROL_MAP_SWAPCIRCLE 0xE

#define SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_COMPLETE 0x80
#define SC_LEVEL_CONTROL_ENVFX_A 0x4F
#define SC_LEVEL_CONTROL_ENVFX_B 0x50
#define SC_LEVEL_CONTROL_ENVFX_C 0x245
#define SC_LEVEL_CONTROL_ENVFX_D 0x246
#define SC_LEVEL_CONTROL_ENVFX_E 0x51

int sc_levelcontrol_processAnimEventsCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    ScLevelControlState* state = obj->extra;
    int i;

    (void)unused;

    animUpdate->movementState = 0;
    for (i = 0; i < (int)(u32)animUpdate->eventCount; i++) {
        int eventId = animUpdate->eventIds[i];
        switch (eventId) {
        case 1:
            sc_levelcontrol_applyAnimEventState(obj, 7);
            break;
        case 2:
            sc_levelcontrol_applyAnimEventState(obj, 5);
            break;
        case 3:
            state->animEventFlags |= SC_LEVEL_CONTROL_ANIM_EVENT_FLAG_3_TRIGGERED;
            break;
        }
    }
    state->animEventFlags |= SC_LEVEL_CONTROL_ANIM_EVENT_FLAG_PROCESSED;
    mainSetBits(0x60f, 0);
    state = obj->extra;
    Obj_GetPlayerObject();
    if (state->animEventState == 5) {
        mainSetBits(0x60f, 1);
        if (isGameTimerDisabled()) {
            if (mainGetBit(0x7a) != 0) {
                mainSetBits(0x85, 1);
            }
            state->exitTimer = 120.0f;
            state->animEventState = 0;
            Sfx_PlayFromObject(0, SFXTRIG_id_10a);
            Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
        }
    }
    return 0;
}

u8 sc_levelcontrol_getAnimEventState(GameObject* obj) {
    return ((ScLevelControlState*)obj->extra)->animEventState;
}

void sc_levelcontrol_applyAnimEventState(GameObject* obj, u8 animEventState) {
    ScLevelControlState* state = obj->extra;
    u8 mode;

    state->animEventState = animEventState;
    mode = state->animEventState;
    if (mode == 2) {
        state->animEventState = 0;
    } else if (mode == 5) {
        mainSetBits(0x2b8, 1);
        mainSetBits(0x4bd, 0);
        mainSetBits(0x85, 0);
        gameTimerInit(GAME_TIMER_COUNT_DOWN | GAME_TIMER_LOOP_SOUND | GAME_TIMER_END_SOUND | GAME_TIMER_DISPLAY,
                      0x96);
        Music_Trigger(MUSICTRIG_CRF_Suspense, 1);
        gameTimerResume();
    } else if (mode == 3) {
        gameTimerInit(GAME_TIMER_COUNT_DOWN | GAME_TIMER_LOOP_SOUND | GAME_TIMER_END_SOUND | GAME_TIMER_DISPLAY,
                      0x3c);
        state->animEventState = 0;
        Music_Trigger(MUSICTRIG_trex_chase, 1);
        gameTimerResume();
    } else if (mode == 6) {
        Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
        state->animEventState = 0;
        state->fadeTimer = 120.0f;
        gameTimerStop();
    } else if (mode == 4) {
        state->animEventState = 0;
        Music_Trigger(MUSICTRIG_trex_chase, 0);
        gameTimerStop();
    }
}

int sc_levelcontrol_getExtraSize(void) {
    return sizeof(ScLevelControlState);
}

int sc_levelcontrol_getObjectTypeId(void) {
    return 0;
}

void sc_levelcontrol_free(GameObject* obj) {
    (void)obj;

    gameTimerStop();
    disableHeavyFog();
    Music_Trigger(MUSICTRIG_PU3_Adventure_c4, 0);
    Music_Trigger(MUSICTRIG_Teleport, 0);
    Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
    Music_Trigger(MUSICTRIG_fox_arwing, 0);
    Music_Trigger(MUSICTRIG_trex_chase, 0);
}

void sc_levelcontrol_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    s32 v = visible;
    if (v != 0) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void sc_levelcontrol_hitDetect(void) {
}

/* Per-frame driver: replays the env-fx set on map (re)entry, advances the
   village mode gates, runs the fade/exit countdown timers, eases the heavy
   fog level, tracks the totem combo code (bits 0x7d..0x7f) into the music
   step, and keeps the area music in sync with the day/night sun position. */
void sc_levelcontrol_update(GameObject* obj) {
    ScLevelControlState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();

    if (obj->userData1 != 0) {
        skySetSlotFlag80(7, 0);
        skySetEnvFxFlags(0);
        if (obj->userData1 == 2) {
            getEnvfxActImmediately(0, 0, SC_LEVEL_CONTROL_ENVFX_A, 0);
            getEnvfxActImmediately(0, 0, SC_LEVEL_CONTROL_ENVFX_B, 0);
            getEnvfxActImmediately(0, 0, SC_LEVEL_CONTROL_ENVFX_C, 0);
            if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE, 5) != 0) {
                getEnvfxActImmediately(0, 0, SC_LEVEL_CONTROL_ENVFX_D, 0);
            } else {
                getEnvfxActImmediately(0, 0, SC_LEVEL_CONTROL_ENVFX_E, 0);
            }
        } else {
            getEnvfxAct(0, 0, SC_LEVEL_CONTROL_ENVFX_A, 0);
            getEnvfxAct(0, 0, SC_LEVEL_CONTROL_ENVFX_B, 0);
            getEnvfxAct(0, 0, SC_LEVEL_CONTROL_ENVFX_C, 0);
            if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE, 5) != 0) {
                getEnvfxAct(0, 0, SC_LEVEL_CONTROL_ENVFX_D, 0);
            } else {
                getEnvfxAct(0, 0, SC_LEVEL_CONTROL_ENVFX_E, 0);
            }
        }
        obj->userData1 = 0;
    }
    if (state->statusFlags.challengeGateGroupEnabled == 0 && mainGetBit(GAMEBIT_LV_ChallengeGate2Complete) != 0) {
        (*gMapEventInterface)->setObjGroupStatus(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE, 0xa, 1);
        state->statusFlags.challengeGateGroupEnabled = 1;
    }
    if (state->playerMapCell != SC_LEVEL_CONTROL_MAP_SWAPCIRCLE) {
        if (coordsToMapCell(player->anim.localPosX, player->anim.localPosZ) == SC_LEVEL_CONTROL_MAP_SWAPCIRCLE) {
            u8 mapAct = ((int (*)(s32))(*gMapEventInterface)->getMapAct)(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE);
            Obj_GetPlayerObject();
            switch (mapAct) {
            case 1:
                if (mainGetBit(GAMEBIT_ITEM_SpellStone2_Used) != 0) {
                    (*gMapEventInterface)->setMapAct(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE, 2);
                }
                break;
            case 2:
            case 3:
            case 4:
            case 5:
                if (mainGetBit(GAMEBIT_LV_EscapedFromPole) != 0) {
                    (*gMapEventInterface)->setMapAct(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE, 6);
                }
                break;
            }
        } else {
            return;
        }
    }
    if (state->fadeTimer && (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
        if (state->fadeTimer == 120.0f) {
            (*gScreenTransitionInterface)->start(0x73, SCREEN_TRANSITION_BLACK);
        }
        state->fadeTimer -= timeDelta;
        if (state->fadeTimer <= 0.0f) {
            state->fadeTimer = 0.0f;
            state->exitTimer = 0.0f;
            mainSetBits(0x2b8, 0);
            mainSetBits(0x4bd, 1);
            mainSetBits(SC_TOTEM_POLE_GAMEBIT_FRONT, 0);
            mainSetBits(SC_TOTEM_POLE_GAMEBIT_LEFT, 0);
            mainSetBits(SC_TOTEM_POLE_GAMEBIT_RIGHT, 0);
            mainSetBits(SC_TOTEM_POLE_GAMEBIT_REAR, 0);
            mainSetBits(0x63e, 1);
            mainSetBits(0x7cf, 1);
        }
    } else if (state->exitTimer && (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
        if (state->exitTimer == 120.0f) {
            (*gScreenTransitionInterface)->start(0x73, SCREEN_TRANSITION_BLACK);
        }
        state->exitTimer -= timeDelta;
        if (state->exitTimer <= 0.0f) {
            mainSetBits(0x640, 1);
            state->exitTimer = 0.0f;
            mainSetBits(0x2b8, 0);
            mainSetBits(0x4bd, 1);
            mainSetBits(SC_TOTEM_POLE_GAMEBIT_FRONT, 0);
            mainSetBits(SC_TOTEM_POLE_GAMEBIT_LEFT, 0);
            mainSetBits(SC_TOTEM_POLE_GAMEBIT_RIGHT, 0);
            mainSetBits(SC_TOTEM_POLE_GAMEBIT_REAR, 0);
        }
    }
    state->playerMapCell = coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);
    if (mainGetBit(0xcdc) != 0) {
        if (state->helpTextTimer > 0.0f) {
            gameTextShow(0x429);
            state->helpTextTimer -= timeDelta;
            if (state->helpTextTimer < 0.0f) {
                state->helpTextTimer = 0.0f;
            }
        }
        if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE, 1) != 0) {
            state->fogNearTarget = -1000.0f;
            state->fogNearStep = 0.35f;
        } else if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE, 5) !=
                   0) {
            state->fogNearTarget = -1200.0f;
            state->fogNearStep = -0.35f;
            if (obj->userData2 != 0) {
                skySetLightIndex(1, 1.0f);
                obj->userData2 = 0;
            }
        } else {
            state->fogNearTarget = -1000.0f;
            state->fogNearStep = 0.35f;
        }
    } else {
        state->fogNearTarget = -1080.0f;
        state->fogNearStep = -0.35f;
    }
    if (state->fogNearTarget != state->fogNear) {
        state->fogNear = state->fogNearStep * timeDelta + state->fogNear;
        if (state->fogNearStep < 0.0f) {
            if (state->fogNear < state->fogNearTarget) {
                state->fogNear = state->fogNearTarget;
            }
        } else if (state->fogNear > state->fogNearTarget) {
            state->fogNear = state->fogNearTarget;
        }
        enableHeavyFog(50.0f + state->fogNear, state->fogNear, 1000.0f, 0.1f, 0.0005f, 0);
    }
    if (mainGetBit(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_1) != 0) {
        mainSetBits(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_1, 0);
        if (gScLevelControlTotemComboSequence[state->totemComboIndex] == SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_1) {
            state->totemComboIndex += 1;
        } else {
            state->totemComboIndex = 0;
        }
    } else if (mainGetBit(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_2) != 0) {
        mainSetBits(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_2, 0);
        if (gScLevelControlTotemComboSequence[state->totemComboIndex] == SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_2) {
            state->totemComboIndex += 1;
        } else {
            state->totemComboIndex = 0;
        }
    } else if (mainGetBit(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_3) != 0) {
        mainSetBits(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_3, 0);
        if (gScLevelControlTotemComboSequence[state->totemComboIndex] == SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_3) {
            state->totemComboIndex += 1;
        } else {
            state->totemComboIndex = 0;
        }
    }
    if (state->totemComboIndex >= 3) {
        mainSetBits(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_COMPLETE, 1);
        state->totemComboIndex = 0;
    }
    if ((state->animEventFlags & SC_LEVEL_CONTROL_ANIM_EVENT_FLAG_PROCESSED) != 0) {
        state->animEventFlags &= ~SC_LEVEL_CONTROL_ANIM_EVENT_FLAG_PROCESSED;
        mainSetBits(0x60f, 1);
        if (mainGetBit(0x7a) == 0) {
            if (mainGetBit(0x627) != 0 && mainGetBit(0x63e) != 0) {
                mainSetBits(GAMEBIT_LV_DoneTests, 1);
            }
        } else if (mainGetBit(GAMEBIT_LV_DoneTests) != 0) {
            mainSetBits(0x85, 1);
        }
    }
    if (state->animEventState == 0) {
        if (mainGetBit(0x60e) != 0) {
            mainSetBits(0x60e, 0);
            timeListPromptOpen();
        }
    } else if (state->animEventState == 5) {
        if (mainGetBit(0x60e) != 0) {
            mainSetBits(0x60e, 0);
            gameTimerStop();
            if (mainGetBit(0x7a) != 0) {
                mainSetBits(0x85, 1);
            }
            state->exitTimer = 120.0f;
            (*gScreenTransitionInterface)->start(0x73, SCREEN_TRANSITION_BLACK);
            state->animEventState = 0;
            Sfx_PlayFromObject(0, SFXTRIG_id_10a);
        }
    }
    if (mainGetBit(GAMEBIT_ITEM_LVBlock2_Used) != 0) {
        mainSetBits(0x612, 1);
        mainSetBits(0x90b, 1);
        mainSetBits(0x87, 1);
    }
    if (mainGetBit(GAMEBIT_ITEM_LVBlock3_Used) != 0) {
        mainSetBits(0x2c6, 1);
        mainSetBits(0x2ce, 1);
        mainSetBits(0xbdc, 1);
    }
    if (mainGetBit(GAMEBIT_ITEM_LVBlock1_Used) != 0) {
        mainSetBits(0xbdf, 1);
        mainSetBits(0xbe1, 1);
        mainSetBits(0xbe3, 1);
    }
    {
        ScLevelControlState* eventState = obj->extra;
        Obj_GetPlayerObject();
        if (eventState->animEventState == 5) {
            mainSetBits(0x60f, 1);
            if (isGameTimerDisabled()) {
                if (mainGetBit(0x7a) != 0) {
                    mainSetBits(0x85, 1);
                }
                eventState->exitTimer = 120.0f;
                eventState->animEventState = 0;
                Sfx_PlayFromObject(0, SFXTRIG_id_10a);
                Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
            }
        }
    }
    if (mainGetBit(0x4d0) == 0) {
        if (mainGetBit(GAMEBIT_LV_CapturedByLightFoot) != 0) {
            mainSetBits(0x4d0, 1);
            (*gMapEventInterface)->setObjGroupStatus(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE, 2, 1);
            warpToMap(0x50, 0);
            (*gMapEventInterface)->setObjGroupStatus(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE, 1, 0);
        }
    }
    if ((*gSkyInterface)->getSunPosition(0) != 0) {
        if (state->musicTriggerId != MUSICTRIG_PU1_Mysterious) {
            state->musicTriggerId = MUSICTRIG_PU1_Mysterious;
            Music_Trigger(MUSICTRIG_PU1_Mysterious, 1);
        }
        if (state->ambientMusicTriggerId != -1) {
            state->ambientMusicTriggerId = -1;
            Music_Trigger(MUSICTRIG_fox_arwing, 0);
        }
    } else {
        if (state->musicTriggerId != MUSICTRIG_KP_Text) {
            state->musicTriggerId = MUSICTRIG_KP_Text;
            Music_Trigger(MUSICTRIG_KP_Text, 1);
        }
        if (state->ambientMusicTriggerId != MUSICTRIG_fox_arwing) {
            state->ambientMusicTriggerId = MUSICTRIG_fox_arwing;
            Music_Trigger(MUSICTRIG_fox_arwing, 1);
        }
    }
    GameBitLatch_Update(&state->musicLatches, 1, -1, -1, 0xe1e, MUSICTRIG_Teleport);
    GameBitLatch_Update(&state->musicLatches, 2, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK, MUSICTRIG_PU3_Adventure_c4);
    if ((state->animEventFlags & SC_LEVEL_CONTROL_ANIM_EVENT_FLAG_3_TRIGGERED) != 0) {
        mainSetBits(0x60e, 1);
        state->animEventFlags &= ~SC_LEVEL_CONTROL_ANIM_EVENT_FLAG_3_TRIGGERED;
    }
}

void sc_levelcontrol_init(GameObject* obj) {
    ScLevelControlState* state = obj->extra;
    f32 fogNear;

    state->statusFlags.challengeGateGroupEnabled = 0;
    state->playerMapCell = 0xff;
    state->animEventState = 0;
    obj->animEventCallback = sc_levelcontrol_processAnimEventsCallback;
    mainSetBits(0x60f, 1);
    mainSetBits(0x2b8, 0);
    mainSetBits(0x4bd, 1);
    mainSetBits(SC_TOTEM_POLE_GAMEBIT_FRONT, 0);
    mainSetBits(SC_TOTEM_POLE_GAMEBIT_LEFT, 0);
    mainSetBits(SC_TOTEM_POLE_GAMEBIT_RIGHT, 0);
    mainSetBits(SC_TOTEM_POLE_GAMEBIT_REAR, 0);
    state->helpTextTimer = 300.0f;
    fogNear = -1200.0f;
    state->fogNear = -1200.0f;
    state->fogNearTarget = fogNear;
    state->fogNearStep = -0.35f;
    enableHeavyFog(50.0f + state->fogNear, state->fogNear, 1000.0f, 0.1f, 0.0005f, 0);
    if (mainGetBit(0x7a) != 0) {
        mainSetBits(0x85, 1);
    }
    unlockLevel(mapGetDirIdx(SC_LEVEL_CONTROL_MAP_SWAPCIRCLE), 0, 0);
    if (getSaveGameLoadStatus() != 0) {
        obj->userData1 = 2;
    } else {
        obj->userData1 = 1;
    }
    obj->userData2 = 1;
}

void sc_levelcontrol_release(void) {
}

void sc_levelcontrol_initialise(void) {
}

ObjectDescriptor12 gSC_levelcontrolObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)sc_levelcontrol_initialise,
    (ObjectDescriptorCallback)sc_levelcontrol_release,
    0,
    (ObjectDescriptorCallback)sc_levelcontrol_init,
    (ObjectDescriptorCallback)sc_levelcontrol_update,
    (ObjectDescriptorCallback)sc_levelcontrol_hitDetect,
    (ObjectDescriptorCallback)sc_levelcontrol_render,
    (ObjectDescriptorCallback)sc_levelcontrol_free,
    (ObjectDescriptorCallback)sc_levelcontrol_getObjectTypeId,
    sc_levelcontrol_getExtraSize,
    (ObjectDescriptorCallback)sc_levelcontrol_applyAnimEventState,
    (ObjectDescriptorCallback)sc_levelcontrol_getAnimEventState,
};
