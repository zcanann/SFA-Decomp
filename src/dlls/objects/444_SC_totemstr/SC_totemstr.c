/*
 * SC_totemstr (DLL 0x1BC): LightFoot Village's Test of Strength against
 * MuscleFoot. Both characters push opposite sides of a rotating mechanism;
 * sufficiently rapid A-button presses push MuscleFoot into the pit.
 */

#include "dlls/objects/444_SC_totemstr.h"

#include "dlls/objects/440_SC_totempol.h"
#include "dlls/objects/443_SC_totembon.h"
#include "dolphin/pad.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_object_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/model_engine.h"
#include "main/obj_list.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/pad.h"
#include "main/screen_transition.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/game_timer_control_api.h"

#define SC_TOTEM_STRENGTH_MAP_LIGHTFOOT           0xE
#define SC_TOTEM_STRENGTH_MAP_EVENT_MODE          6
#define SC_TOTEM_STRENGTH_CAMERA_MODE             0x48
#define SC_TOTEM_STRENGTH_A_BUTTON_ICON           0xF
#define SC_TOTEM_STRENGTH_ANCHOR_SEQUENCE_ID      0x3FF
#define SC_TOTEM_STRENGTH_PLAYER_PULL_MOVE        0x401
#define SC_TOTEM_STRENGTH_IDLE_PULL_MOVE          0
#define SC_TOTEM_STRENGTH_SEQUENCE_READY_INDEX    0x19
#define SC_TOTEM_STRENGTH_INITIAL_TRACK_OFFSET    (-0x2900)
#define SC_TOTEM_STRENGTH_WIN_TRACK_OFFSET        (-0x46DC)
#define SC_TOTEM_STRENGTH_LOSS_TRACK_OFFSET       (-0xB24)
#define SC_TOTEM_STRENGTH_SCREEN_TRANSITION       0x14
#define SC_TOTEM_STRENGTH_CAMERA_PRIORITY         0xFF
#define SC_TOTEM_STRENGTH_GAMEBIT_WON             0x784
#define SC_TOTEM_STRENGTH_GAMEBIT_LOST            0x786
#define SC_TOTEM_STRENGTH_GAMEBIT_SEQUENCE_ACTIVE 0xF1D

#define SC_TOTEM_STRENGTH_TRIGGER_MASK    0x03
#define SC_TOTEM_STRENGTH_TRIGGER_FLAG_01 0x01
#define SC_TOTEM_STRENGTH_TRIGGER_FLAG_02 0x02
#define SC_TOTEM_STRENGTH_FLAG_ACTIVE     0x04
#define SC_TOTEM_STRENGTH_FLAG_WON        0x08
#define SC_TOTEM_STRENGTH_FLAG_LOST       0x10

u16 gScTotemStrengthRecordGameBits[SC_TOTEM_STRENGTH_RECORD_GAME_BIT_COUNT] = {
    GAMEBIT_LV_TestStrengthBestTime1,
    GAMEBIT_LV_TestStrengthBestTime2,
    GAMEBIT_LV_TestStrengthBestTime3,
    0,
};

int gTotemStrengthDeactivateTimer;

/*
 * Runs the tug-of-war minigame. Resolves the anchor object, applies sequence
 * events, advances the rope from A-button presses, drives both pull animations
 * and their sounds, and starts the ending transition when either side wins.
 */
int sc_totemstrength_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    GameObject* self;
    ScTotemStrengthState* state;
    GameObject* playerObject;
    GameObject* player;
    GameObject** objects;
    GameObject* totemPole;
    int i;
    u8 eventId;
    int buttons;
    f32 wob1, wob2, push;
    f32 diff;
    f32 absDiff;
    f32 progress;
    int volume;
    int result;
    int idx1, cnt1, cnt2, idx2, cnt3, idx3, cnt4, idx4, cnt5, idx5;
    struct {
        int mode;
        u8 flag;
    } cameraEvent;

    (void)unused;

    self = obj;
    state = self->extra;
    playerObject = Obj_GetPlayerObject();
    player = playerObject;
    state->flags = (u8)(state->flags | SC_TOTEM_STRENGTH_FLAG_ACTIVE);
    setAButtonIcon(SC_TOTEM_STRENGTH_A_BUTTON_ICON);
    gTotemStrengthDeactivateTimer = 0;
    state->linkedObject = NULL;
    objects = ObjList_GetObjects(&idx1, &cnt1);
    while (idx1 < cnt1) {
        state->linkedObject = objects[idx1++];
        if (state->linkedObject->anim.romDefNo == SC_TOTEM_STRENGTH_ANCHOR_SEQUENCE_ID) {
            idx1 = cnt1;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++) {
        eventId = animUpdate->eventIds[i];
        switch (eventId) {
        case 1:
            state->flags = (u8)(state->flags | SC_TOTEM_STRENGTH_TRIGGER_FLAG_01);
            break;
        case 2:
            state->flags = (u8)(state->flags | SC_TOTEM_STRENGTH_TRIGGER_FLAG_02);
            state->transitionStep = 0;
            (*gObjectTriggerInterface)->setCamVars(SC_TOTEM_STRENGTH_CAMERA_MODE, 3, 0, 0);
            break;
        case 3:
            objects = ObjList_GetObjects(&idx2, &cnt2);
            for (; idx2 < cnt2; idx2++) {
                if (objects[idx2] != self && objects[idx2]->anim.romDefNo == SC_TOTEM_POLE_SEQUENCE_ID) {
                    totemPole = objects[idx2];
                    (*(ScTotemPoleInterfaceVTable**)totemPole->anim.dll)->handleEvent(totemPole, 2);
                    break;
                }
            }
            break;
        case 4:
            objects = ObjList_GetObjects(&idx3, &cnt3);
            for (; idx3 < cnt3; idx3++) {
                if (objects[idx3] != self && objects[idx3]->anim.romDefNo == SC_TOTEM_POLE_SEQUENCE_ID) {
                    totemPole = objects[idx3];
                    (*(ScTotemPoleInterfaceVTable**)totemPole->anim.dll)->handleEvent(totemPole, 3);
                    break;
                }
            }
            break;
        case 5:
            if (state->linkedObject != NULL) {
                playerObject->anim.currentMoveProgress = 0.5f;
                state->linkedObject->anim.currentMoveProgress = 0.5f;
                ObjAnim_SetCurrentMove(player, SC_TOTEM_STRENGTH_PLAYER_PULL_MOVE,
                                       playerObject->anim.currentMoveProgress, 0);
                ObjAnim_SetCurrentMove(state->linkedObject, SC_TOTEM_STRENGTH_IDLE_PULL_MOVE,
                                       state->linkedObject->anim.currentMoveProgress, 0);
                state->prevTrackOffset = state->currentTrackOffset;
            }
            break;
        }
    }
    if ((state->flags & SC_TOTEM_STRENGTH_TRIGGER_MASK) == 0) {
        result = 0;
    } else if (state->sequenceIndex < SC_TOTEM_STRENGTH_SEQUENCE_READY_INDEX) {
        result = 0;
    } else {
        if ((*gCameraInterface)->getMode() != SC_TOTEM_STRENGTH_CAMERA_MODE) {
            cameraEvent.mode = 3;
            cameraEvent.flag = 1;
            (*gCameraInterface)
                ->setMode(SC_TOTEM_STRENGTH_CAMERA_MODE, 1, 3, 8, &cameraEvent, 0, SC_TOTEM_STRENGTH_CAMERA_PRIORITY);
        }
        if (playerObject->anim.currentMove != SC_TOTEM_STRENGTH_PLAYER_PULL_MOVE) {
            ObjAnim_SetCurrentMove(player, SC_TOTEM_STRENGTH_PLAYER_PULL_MOVE, playerObject->anim.currentMoveProgress,
                                   0);
        }
        totemPole = state->linkedObject;
        if (totemPole->anim.currentMove != SC_TOTEM_STRENGTH_IDLE_PULL_MOVE) {
            ObjAnim_SetCurrentMove(totemPole, SC_TOTEM_STRENGTH_IDLE_PULL_MOVE,
                                   totemPole->anim.currentMoveProgress, 0);
        }
        animUpdate->flags = -1;
        animUpdate->movementState = 0;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_blockscrape_lp);
        for (i = 0; i < framesThisStep; i++) {
            if (state->linkedObject == NULL) {
                return 0;
            }
            wob1 = (f32)(state->currentTrackOffset + 0xb24) / -15288.0f;
            wob2 = 2.0f * wob1 + -1.0f;
            if (wob2 < 0.0f) {
                wob2 = -wob2;
            }
            push = 1.7f * wob1 + 0.2f;
            push = push * wob2 + 1.0f;
            buttons = getButtonsJustPressedIfNotBusy(0);
            if ((buttons & PAD_BUTTON_A) != 0 && isGameTimerDisabled() == 0) {
                state->offsetVelocity -= 2.7f;
            }
            if (state->offsetVelocity < -40.0f) {
                state->offsetVelocity = -40.0f;
            }
            if (state->currentTrackOffset >= SC_TOTEM_STRENGTH_WIN_TRACK_OFFSET &&
                state->currentTrackOffset <= SC_TOTEM_STRENGTH_LOSS_TRACK_OFFSET) {
                state->currentTrackOffset = (f32)state->currentTrackOffset + state->offsetVelocity;
            }
            diff = ((f32)state->prevTrackOffset - state->currentTrackOffset) / 40.0f;
            if (state->currentTrackOffset < SC_TOTEM_STRENGTH_WIN_TRACK_OFFSET) {
                state->transitionStep = 0;
                state->flags = (u8)(state->flags & ~SC_TOTEM_STRENGTH_TRIGGER_MASK);
                state->flags = (u8)(state->flags | SC_TOTEM_STRENGTH_FLAG_WON);
                objects = ObjList_GetObjects(&idx4, &cnt4);
                for (; idx4 < cnt4; idx4++) {
                    if (objects[idx4] != self && objects[idx4]->anim.romDefNo == SC_TOTEM_POLE_SEQUENCE_ID) {
                        totemPole = objects[idx4];
                        (*(ScTotemPoleInterfaceVTable**)totemPole->anim.dll)->handleEvent(totemPole, 4);
                        break;
                    }
                }
                sc_totembond_insertOrderedGameBit(gScTotemStrengthRecordGameBits,
                                                  gameTimerGetElapsedMilliseconds() / 10.0f);
                setHudForceShowMask(0);
                if (state->sequenceIndex > 0) {
                    ObjSeq_takeXrotChanged(state->sequenceIndex);
                }
                (*gScreenTransitionInterface)->step(SC_TOTEM_STRENGTH_SCREEN_TRANSITION, SCREEN_TRANSITION_BLACK);
                gTotemStrengthDeactivateTimer = 2;
                return 4;
            }
            if (state->currentTrackOffset > SC_TOTEM_STRENGTH_LOSS_TRACK_OFFSET) {
                state->transitionStep = 3;
                state->flags = (u8)(state->flags & ~SC_TOTEM_STRENGTH_TRIGGER_MASK);
                state->flags = (u8)(state->flags | SC_TOTEM_STRENGTH_FLAG_LOST);
                objects = ObjList_GetObjects(&idx5, &cnt5);
                for (; idx5 < cnt5; idx5++) {
                    if (objects[idx5] != self && objects[idx5]->anim.romDefNo == SC_TOTEM_POLE_SEQUENCE_ID) {
                        totemPole = objects[idx5];
                        (*(ScTotemPoleInterfaceVTable**)totemPole->anim.dll)->handleEvent(totemPole, 4);
                        break;
                    }
                }
                setHudForceShowMask(0);
                if (state->sequenceIndex > 0) {
                    ObjSeq_takeXrotChanged(state->sequenceIndex);
                }
                (*gScreenTransitionInterface)->step(SC_TOTEM_STRENGTH_SCREEN_TRANSITION, SCREEN_TRANSITION_BLACK);
                gTotemStrengthDeactivateTimer = 2;
                return 4;
            }
            if (state->sequenceIndex > 0) {
                (*gObjectTriggerInterface)->setXrot(state->sequenceIndex, state->currentTrackOffset);
            }
            if (state->offsetVelocity < 40.0f) {
                state->offsetVelocity = 0.19f * push + state->offsetVelocity;
            }
            if (ObjAnim_AdvanceCurrentMove(player, ((f32)state->prevTrackOffset - state->currentTrackOffset) / 9500.0f,
                                           timeDelta, 0) != 0 &&
                playerObject->anim.currentMoveProgress < 0.0f) {
                playerObject->anim.currentMoveProgress = 1.0f + playerObject->anim.currentMoveProgress;
            }
            if (ObjAnim_AdvanceCurrentMove(state->linkedObject,
                                           ((f32)state->currentTrackOffset - state->prevTrackOffset) / 9500.0f,
                                           timeDelta, 0) != 0) {
                progress = state->linkedObject->anim.currentMoveProgress;
                if (progress < 0.0f) {
                    state->linkedObject->anim.currentMoveProgress = 1.0f + progress;
                }
            }
            state->prevTrackOffset = state->currentTrackOffset;
        }
        state->playerSfxTimer -= timeDelta;
        if (state->playerSfxTimer < 0.0f) {
            if (diff < 0.0f) {
                state->playerSfxTimer = randomGetRange(0x28, 100);
            } else {
                state->playerSfxTimer = randomGetRange(0x78, 0xf0);
            }
            Sfx_PlayFromObject(playerObject, SFXTRIG_literun116_var);
        }
        state->platformSfxTimer -= timeDelta;
        if (state->platformSfxTimer < 0.0f) {
            if (diff > 0.0f) {
                state->platformSfxTimer = randomGetRange(0x28, 100);
            } else {
                state->platformSfxTimer = randomGetRange(0x78, 0xf0);
            }
            Sfx_PlayFromObject(obj, SFXTRIG_spotfox03);
        }
        if (diff < 0.0f) {
            absDiff = -diff;
        } else {
            absDiff = diff;
        }
        volume = (int)(100.0f * absDiff);
        if (volume > 100) {
            volume = 100;
        }
        Sfx_SetObjectSfxVolume(obj, SFXTRIG_blockscrape_lp, volume & 0xff, 127.0f);
        result = 0;
    }

    return result;
}

int sc_totemstrength_getExtraSize(void) {
    return sizeof(ScTotemStrengthState);
}

int sc_totemstrength_getObjectTypeId(void) {
    return 0;
}

void sc_totemstrength_free(void) {
}

void sc_totemstrength_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                             s8 visible) {
    (void)visible;

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void sc_totemstrength_hitDetect(void) {
}

/*
 * Drives the tug-of-war intro and outro while the LightFoot Village map event
 * is in the minigame state.
 */
void sc_totemstrength_update(GameObject* obj) {
    ScTotemStrengthState* state = obj->extra;
    u8 mapMode;
    s16 step;
    u8 flags;
    f32 zero;

    Obj_GetPlayerObject();
    mainSetBits(SC_TOTEM_STRENGTH_GAMEBIT_SEQUENCE_ACTIVE, 0);
    mapMode = (*gMapEventInterface)->getMapAct(SC_TOTEM_STRENGTH_MAP_LIGHTFOOT);
    if (mapMode == SC_TOTEM_STRENGTH_MAP_EVENT_MODE) {
        if ((state->flags & SC_TOTEM_STRENGTH_FLAG_ACTIVE) != 0) {
            if (state->sequenceIndex > 0) {
                (*gObjectTriggerInterface)->endSequence(state->sequenceIndex);
                ObjSeq_takeXrotChanged(state->sequenceIndex);
            }
            if (gTotemStrengthDeactivateTimer-- == 0) {
                state->flags = (u8)(state->flags & ~SC_TOTEM_STRENGTH_FLAG_ACTIVE);
                obj->anim.localPosX = state->savedPosX;
                obj->anim.localPosY = state->savedPosY;
                obj->anim.localPosZ = state->savedPosZ;
                state->linkedObject = NULL;
                obj->anim.rotX = SC_TOTEM_STRENGTH_INITIAL_TRACK_OFFSET;
                state->currentTrackOffset = SC_TOTEM_STRENGTH_INITIAL_TRACK_OFFSET;
                flags = state->flags;
                if ((flags & SC_TOTEM_STRENGTH_FLAG_WON) != 0) {
                    mainSetBits(SC_TOTEM_STRENGTH_GAMEBIT_WON, 1);
                    state->sequenceIndex = -1;
                    state->flags = (u8)(state->flags & ~SC_TOTEM_STRENGTH_TRIGGER_MASK);
                    state->flags = (u8)(state->flags & ~SC_TOTEM_STRENGTH_FLAG_WON);
                } else if ((flags & SC_TOTEM_STRENGTH_FLAG_LOST) != 0) {
                    state->flags = (u8)(flags & ~SC_TOTEM_STRENGTH_FLAG_LOST);
                    state->sequenceIndex = -1;
                    mainSetBits(SC_TOTEM_STRENGTH_GAMEBIT_LOST, 1);
                }
            }
        } else if ((state->flags & SC_TOTEM_STRENGTH_TRIGGER_FLAG_02) != 0) {
            step = state->transitionStep;
            if (step == 0) {
                obj->anim.rotX = SC_TOTEM_STRENGTH_INITIAL_TRACK_OFFSET;
                state->currentTrackOffset = SC_TOTEM_STRENGTH_INITIAL_TRACK_OFFSET;
                state->prevTrackOffset = state->currentTrackOffset;
                zero = 0.0f;
                state->unknown04 = 0.0f;
                state->offsetVelocity = zero;
                state->transitionStep = 1;
                state->flags = (u8)(state->flags & ~SC_TOTEM_STRENGTH_TRIGGER_FLAG_01);
            } else if (step == 1) {
                mainSetBits(SC_TOTEM_STRENGTH_GAMEBIT_SEQUENCE_ACTIVE, 1);
                setHudForceShowMask(1);
                state->sequenceIndex = (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            } else if (step == 2) {
                state->transitionStep = 0;
            } else if (step == 3) {
                state->transitionStep = 0;
            }
        }
    }
}

void sc_totemstrength_init(GameObject* obj) {
    ScTotemStrengthState* state = obj->extra;

    obj->animEventCallback = sc_totemstrength_animEventCallback;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->anim.rotX = (s16)SC_TOTEM_STRENGTH_INITIAL_TRACK_OFFSET;
    state->currentTrackOffset = SC_TOTEM_STRENGTH_INITIAL_TRACK_OFFSET;
    state->transitionStep = 0;
    state->linkedObject = NULL;
    state->savedPosX = obj->anim.localPosX;
    state->savedPosY = obj->anim.localPosY;
    state->savedPosZ = obj->anim.localPosZ;
}

void sc_totemstrength_release(void) {
}

void sc_totemstrength_initialise(void) {
}

ObjectDescriptor gSC_totemstrengthObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)sc_totemstrength_initialise,
    (ObjectDescriptorCallback)sc_totemstrength_release,
    0,
    (ObjectDescriptorCallback)sc_totemstrength_init,
    (ObjectDescriptorCallback)sc_totemstrength_update,
    (ObjectDescriptorCallback)sc_totemstrength_hitDetect,
    (ObjectDescriptorCallback)sc_totemstrength_render,
    (ObjectDescriptorCallback)sc_totemstrength_free,
    (ObjectDescriptorCallback)sc_totemstrength_getObjectTypeId,
    sc_totemstrength_getExtraSize,
};
