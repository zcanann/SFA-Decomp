/*
 * DBSH_Symbol (DLL 0x196) - Dark Ice Mines shrine spinning symbol.
 *
 * Trigger sequence 0 lets the player rotate this symbol and its paired
 * symbol. The shrine's shared game bits report whether the spin completed.
 */
#include "dlls/objects/406_DBSH_Symbol.h"

#include "dlls/objects/405_DBSH_Shrine.h"
#include "dolphin/pad.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_object_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/game_timer_control_api.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/obj_list.h"
#include "main/objseq.h"
#include "main/pad.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define DBSH_SYMBOL_PARTNER_SEQUENCE_ID 0x20F
#define DBSH_SYMBOL_SPIN_COMPLETE       0x7EF4

#define DBSH_SYMBOL_TIMER_ID       0x1D
#define DBSH_SYMBOL_TIMER_DURATION 0x3C
#define DBSH_SYMBOL_YIELD_REASON   0xBD

#define DBSH_SYMBOL_INPUT_PORT 0

#define DBSH_SYMBOL_SPIN_IMPULSE         14.8f
#define DBSH_SYMBOL_MAX_FORWARD_SPEED    80.0f
#define DBSH_SYMBOL_MAX_REVERSE_SPEED    -300.0f
#define DBSH_SYMBOL_FORWARD_DECELERATION 1.6f
#define DBSH_SYMBOL_REVERSE_DECELERATION 10.1f
#define DBSH_SYMBOL_ANIMATION_STEP_SCALE 7500.0f
#define DBSH_SYMBOL_VOLUME_SPEED_SCALE   4.0f
#define DBSH_SYMBOL_MAX_SFX_VOLUME       100
#define DBSH_SYMBOL_INITIAL_Y_OFFSET     50.0f
#define DBSH_SYMBOL_SFX_TIMER_SHORT_MIN  0x28
#define DBSH_SYMBOL_SFX_TIMER_SHORT_MAX  0x64
#define DBSH_SYMBOL_SFX_TIMER_LONG_MIN   0x78
#define DBSH_SYMBOL_SFX_TIMER_LONG_MAX   0xF0
#define DBSH_SYMBOL_SFX_VOLUME_SCALE     127.0f
#define DBSH_SYMBOL_SFX_CHANNEL          0x7F

typedef enum DBSHSymbolPhase {
    DBSH_SYMBOL_PHASE_HIDE = 0,
    DBSH_SYMBOL_PHASE_PLAY_SCUFF = 1,
    DBSH_SYMBOL_PHASE_START_SEQUENCE = 2,
    DBSH_SYMBOL_PHASE_RESOLVE = 3,
} DBSHSymbolPhase;

enum {
    DBSH_SYMBOL_ANIM_EVENT_START = 1,
};

u8 gDBSHSymbolScuffSfxEnabled = 1;

int dbshSymbol_processAnimEvents(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int volume;
    GameObject** objectList;
    int objectIndex;
    int objectCount;
    int i;
    int buttons;
    DBSHSymbolState* state;
    GameObject* player;

    (void)unused;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    Sfx_SetObjectSfxVolume(obj, SFXTRIG_blockscrape_lp, 10, DBSH_SYMBOL_SFX_VOLUME_SCALE);
    Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_blockscrape_lp);
    animUpdate->movementState = 0;
    for (i = 0; i < animUpdate->eventCount; i++) {
        if (animUpdate->eventIds[i] == DBSH_SYMBOL_ANIM_EVENT_START) {
            gameTimerInit(DBSH_SYMBOL_TIMER_ID, DBSH_SYMBOL_TIMER_DURATION);
            timerSetToCountUp();
            state->flags.sequenceInactive = 0;
            obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
        }
    }
    if (state->flags.sequenceInactive != 0) {
        return 0;
    }
    if (state->partnerSymbol == NULL) {
        objectList = ObjList_GetObjects(&objectIndex, &objectCount);
        while (objectIndex < objectCount) {
            state->partnerSymbol = objectList[objectIndex];
            if (state->partnerSymbol->anim.romDefNo == DBSH_SYMBOL_PARTNER_SEQUENCE_ID) {
                break;
            }
            objectIndex++;
        }
    }
    if (state->partnerSymbol == NULL) {
        return 0;
    }
    for (i = 0; i < framesThisStep; i++) {
        if (isGameTimerDisabled() != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16);
            state->flags.spinCompleted = 0;
            state->flags.sequenceInactive = 1;
            (*gObjectTriggerInterface)->yield(animUpdate, DBSH_SYMBOL_YIELD_REASON);
        }
        buttons = getButtonsJustPressedIfNotBusy(DBSH_SYMBOL_INPUT_PORT);
        if ((buttons & PAD_BUTTON_A) != 0) {
            state->spinSpeed += DBSH_SYMBOL_SPIN_IMPULSE;
        }
        if (state->spinSpeed > DBSH_SYMBOL_MAX_FORWARD_SPEED) {
            state->spinSpeed = DBSH_SYMBOL_MAX_FORWARD_SPEED;
        }
        state->spinProgress += state->spinSpeed;
        if (state->spinProgress >= DBSH_SYMBOL_SPIN_COMPLETE) {
            gameTimerStop();
            Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16);
            ObjAnim_SetCurrentMove(player, 0, 0.0f, 0);
            state->flags.spinCompleted = 1;
            state->flags.sequenceInactive = 1;
            state->spinProgress = DBSH_SYMBOL_SPIN_COMPLETE;
            (*gObjectTriggerInterface)->yield(animUpdate, DBSH_SYMBOL_YIELD_REASON);
            return 0;
        }
        (*gObjectTriggerInterface)->setXrot(state->sequenceHandle, state->spinProgress);
        if (state->spinProgress < 0) {
            state->spinProgress = 0;
            if (state->spinSpeed < 0.0f) {
                state->spinSpeed = 0.0f;
            }
            state->previousSpinProgress = state->spinProgress;
            if (state->spinSpeed > DBSH_SYMBOL_MAX_REVERSE_SPEED) {
                state->spinSpeed -= DBSH_SYMBOL_REVERSE_DECELERATION;
            }
            return 0;
        }
        if (state->spinSpeed > -DBSH_SYMBOL_MAX_FORWARD_SPEED) {
            state->spinSpeed -= DBSH_SYMBOL_FORWARD_DECELERATION;
        }
        if (ObjAnim_AdvanceCurrentMove(
                player, ((f32)state->spinProgress - state->previousSpinProgress) / DBSH_SYMBOL_ANIMATION_STEP_SCALE,
                timeDelta, NULL) != 0) {
            if (player->anim.currentMoveProgress < 0.0f) {
                player->anim.currentMoveProgress =
                    1.0f + player->anim.currentMoveProgress;
            }
        }
        if (state->partnerSymbol != NULL) {
            if (ObjAnim_AdvanceCurrentMove(state->partnerSymbol,
                                           -((f32)state->spinProgress - state->previousSpinProgress) /
                                               DBSH_SYMBOL_ANIMATION_STEP_SCALE,
                                           timeDelta, NULL) != 0) {
                f32 partnerProgress = state->partnerSymbol->anim.currentMoveProgress;
                if (partnerProgress < 0.0f) {
                    state->partnerSymbol->anim.currentMoveProgress = 1.0f + partnerProgress;
                }
            }
        }
        state->previousSpinProgress = state->spinProgress;
    }
    state->playerSfxTimer -= timeDelta;
    if (state->playerSfxTimer < 0.0f) {
        if (state->spinSpeed < 0.0f) {
            state->playerSfxTimer =
                (f32)randomGetRange(DBSH_SYMBOL_SFX_TIMER_SHORT_MIN, DBSH_SYMBOL_SFX_TIMER_SHORT_MAX);
        } else {
            state->playerSfxTimer =
                (f32)randomGetRange(DBSH_SYMBOL_SFX_TIMER_LONG_MIN, DBSH_SYMBOL_SFX_TIMER_LONG_MAX);
        }
        Sfx_PlayFromObject(player, SFXTRIG_literun116_var);
    }
    state->objectSfxTimer -= timeDelta;
    if (state->objectSfxTimer < 0.0f) {
        if (state->spinSpeed > 0.0f) {
            state->objectSfxTimer =
                (f32)randomGetRange(DBSH_SYMBOL_SFX_TIMER_SHORT_MIN, DBSH_SYMBOL_SFX_TIMER_SHORT_MAX);
        } else {
            state->objectSfxTimer =
                (f32)randomGetRange(DBSH_SYMBOL_SFX_TIMER_LONG_MIN, DBSH_SYMBOL_SFX_TIMER_LONG_MAX);
        }
        Sfx_PlayFromObject(obj, SFXTRIG_spotfox03);
    }
    {
        f32 absoluteSpeed = (DBSH_SYMBOL_VOLUME_SPEED_SCALE * state->spinSpeed >= 0.0f)
                                ? DBSH_SYMBOL_VOLUME_SPEED_SCALE * state->spinSpeed
                                : -(DBSH_SYMBOL_VOLUME_SPEED_SCALE * state->spinSpeed);

        volume = (int)absoluteSpeed;
        if (volume > DBSH_SYMBOL_MAX_SFX_VOLUME) {
            volume = DBSH_SYMBOL_MAX_SFX_VOLUME;
        }
        Sfx_SetObjectSfxVolume(obj, SFXTRIG_blockscrape_lp, volume, DBSH_SYMBOL_SFX_VOLUME_SCALE);
    }
    return 0;
}

int dbshSymbol_getExtraSize(void) {
    return sizeof(DBSHSymbolState);
}

void dbshSymbol_free(void) {
    gameTimerStop();
}

void dbshSymbol_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    (void)visible;
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void dbshSymbol_update(GameObject* obj) {
    s16 phase;
    u32 symbolsRaised;
    DBSHSymbolState* state;

    state = obj->extra;
    symbolsRaised = mainGetBit(DBSH_GAMEBIT_SYMBOL_RISE_COMPLETE);
    if (symbolsRaised == 0) {
        state->phase = DBSH_SYMBOL_PHASE_HIDE;
        state->partnerSymbol = NULL;
        mainSetBits(DBSH_GAMEBIT_SYMBOL_SPIN_FAILED, 0);
    } else {
        phase = state->phase;
        if (phase == DBSH_SYMBOL_PHASE_HIDE) {
            obj->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_VISIBLE;
            state->phase = DBSH_SYMBOL_PHASE_PLAY_SCUFF;
        } else if (phase == DBSH_SYMBOL_PHASE_START_SEQUENCE) {
            state->phase = DBSH_SYMBOL_PHASE_RESOLVE;
            state->sequenceHandle = (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        } else if (phase == DBSH_SYMBOL_PHASE_PLAY_SCUFF) {
            if (gDBSHSymbolScuffSfxEnabled != 0) {
                gDBSHSymbolScuffSfxEnabled = 0;
                Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16);
            }
            state->phase = DBSH_SYMBOL_PHASE_START_SEQUENCE;
            gDBSHSymbolScuffSfxEnabled = 1;
        } else if (phase == DBSH_SYMBOL_PHASE_RESOLVE) {
            obj->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_VISIBLE;
            if (state->flags.spinCompleted != 0) {
                mainSetBits(DBSH_GAMEBIT_SYMBOL_SPIN_SUCCEEDED, 1);
            } else {
                mainSetBits(DBSH_GAMEBIT_SYMBOL_SPIN_FAILED, 1);
            }
            Sfx_StopObjectChannel(obj, DBSH_SYMBOL_SFX_CHANNEL);
            state->flags.sequenceInactive = 1;
        }
    }
}

void dbshSymbol_init(GameObject* obj) {
    DBSHSymbolState* state = obj->extra;

    state->spinSpeed = 0.0f;
    state->spinProgress = 0;
    state->previousSpinProgress = 0;
    state->phase = DBSH_SYMBOL_PHASE_HIDE;
    state->partnerSymbol = NULL;
    state->flags.spinCompleted = 0;
    state->flags.sequenceInactive = 1;

    obj->anim.localPosY -= DBSH_SYMBOL_INITIAL_Y_OFFSET;
    obj->animEventCallback = dbshSymbol_processAnimEvents;

    obj->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_VISIBLE;
}

ObjectDescriptor gDBSHSymbolObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dbshSymbol_init,
    (ObjectDescriptorCallback)dbshSymbol_update,
    0,
    (ObjectDescriptorCallback)dbshSymbol_render,
    (ObjectDescriptorCallback)dbshSymbol_free,
    0,
    dbshSymbol_getExtraSize,
};
