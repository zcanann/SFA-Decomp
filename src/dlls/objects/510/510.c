/* PressureSwitch behavior (DLL 510 / 0x01FE). */
#include "dlls/objects/510.h"

#include "game/objects/object.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

/* Sequence IDs for objects that interact with the switch. */
#define PRESSURE_SWITCH_TRIGGER_SEQ_ID 0x6D
#define PRESSURE_SWITCH_CHIME_SEQ_ID   0x146

#define PRESSURE_SWITCH_EVENT_SLOT             11
#define PRESSURE_SWITCH_TRICKY_TRIGGER_MAP_ACT 3
#define PRESSURE_SWITCH_CAMERA_MAP_ACT         1

#define PRESSURE_SWITCH_HOLD_FRAMES              5
#define PRESSURE_SWITCH_RETRIGGER_FRAMES_PER_SEC 60
#define PRESSURE_SWITCH_INITIAL_HOLD_FRAMES      30
#define PRESSURE_SWITCH_MOVE_SFX_CHANNEL         8

#define PRESSURE_SWITCH_PLAYER_FAR_DISTANCE      100.0f
#define PRESSURE_SWITCH_TRICKY_TRIGGER_DISTANCE  50.0f
#define PRESSURE_SWITCH_CONTACT_HEIGHT_THRESHOLD 7.0f
#define PRESSURE_SWITCH_PRESS_DEPTH              5.0f
#define PRESSURE_SWITCH_CAMERA_MIN_DEPTH         2.5f
#define PRESSURE_SWITCH_CAMERA_MAX_DEPTH         5.0f
#define PRESSURE_SWITCH_PRESS_SPEED              0.25f
#define PRESSURE_SWITCH_RISE_SPEED               0.125f
#define PRESSURE_SWITCH_INITIAL_PRESS_DEPTH      25.0f

int PressureSwitch_SeqFn(GameObject* unusedObj, int unused, ObjSeqState* animUpdate) {
    animUpdate->flags = -1;
    animUpdate->movementState = 0;
    return 0;
}

int PressureSwitch_getExtraSize(void) {
    return sizeof(PressureSwitchState);
}

int PressureSwitch_getObjectTypeId(void) {
    return 0;
}

void PressureSwitch_free(void) {
}

void PressureSwitch_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void PressureSwitch_hitDetect(void) {
}

void PressureSwitch_update(GameObject* obj) {
    const PressureSwitchPlacementView* placement;
    PressureSwitchState* state;
    ObjHitboxTransformState* contactState;
    s8 isPlayerFar;
    int contactIndex;
    GameObject* player;
    GameObject* tricky;
    s8 mapSlot;
    int mapGameBit;
    s8 isMoving;
    f32 currentY;
    f32 targetY;
    f32 contactHeightThreshold;
    f32 verticalOffset;

    player = Obj_GetPlayerObject();
    placement = (const PressureSwitchPlacementView*)obj->anim.placement;
    state = obj->extra;
    isPlayerFar = 0;
    if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) > PRESSURE_SWITCH_PLAYER_FAR_DISTANCE) {
        isPlayerFar = 1;
    }
    state->holdTimer--;
    if (state->holdTimer < 0) {
        state->holdTimer = 0;
        state->chimeLatch = 0;
    }
    state->flags.triggerObjectPresent = 0;
    if (obj->anim.hitboxTransformState != NULL && obj->anim.hitboxTransformState->contactObjectCount > 0) {
        state->retriggerTimer = (s16)(placement->retriggerDelay * PRESSURE_SWITCH_RETRIGGER_FRAMES_PER_SEC);
        contactIndex = 0;
        contactHeightThreshold = PRESSURE_SWITCH_CONTACT_HEIGHT_THRESHOLD;
        for (; contactIndex < (contactState = obj->anim.hitboxTransformState)->contactObjectCount; contactIndex++) {
            GameObject* contact = contactState->contactObjects[contactIndex];
            if (contact->anim.romDefNo == PRESSURE_SWITCH_TRIGGER_SEQ_ID) {
                state->flags.triggerObjectPresent = 1;
            }
            if (contact->anim.localPosY - obj->anim.localPosY > contactHeightThreshold) {
                state->holdTimer = PRESSURE_SWITCH_HOLD_FRAMES;
            }
            if (state->chimeLatch == 0 && contact != NULL && contact->anim.romDefNo == PRESSURE_SWITCH_CHIME_SEQ_ID) {
                if (isPlayerFar == 0) {
                    Sfx_PlayFromObject(obj, SFXTRIG_mpick1_b);
                }
                state->chimeLatch = 1;
            }
        }
    } else {
        mapSlot = obj->anim.mapEventSlot;
        if (mapSlot == PRESSURE_SWITCH_EVENT_SLOT &&
            (*gMapEventInterface)->getMapAct(mapSlot) == PRESSURE_SWITCH_TRICKY_TRIGGER_MAP_ACT &&
            (tricky = getTrickyObject()) != NULL &&
            Vec_distance(&obj->anim.worldPosX, &tricky->anim.worldPosX) < PRESSURE_SWITCH_TRICKY_TRIGGER_DISTANCE) {
            state->holdTimer = PRESSURE_SWITCH_HOLD_FRAMES;
        }
    }
    mapSlot = obj->anim.mapEventSlot;
#if defined(VERSION_GSAP01_rev1)
    if (mapSlot == PRESSURE_SWITCH_EVENT_SLOT &&
        (*gMapEventInterface)->getMapAct(mapSlot) == PRESSURE_SWITCH_CAMERA_MAP_ACT) {
#else
    if (mapSlot == PRESSURE_SWITCH_EVENT_SLOT &&
        (*gMapEventInterface)->getMapAct(mapSlot) == PRESSURE_SWITCH_CAMERA_MAP_ACT && isPlayerFar == 0) {
#endif
        if (state->holdTimer != 0) {
            verticalOffset = placement->base.posY - obj->anim.localPosY;
            if (verticalOffset > PRESSURE_SWITCH_CAMERA_MIN_DEPTH &&
                verticalOffset < PRESSURE_SWITCH_CAMERA_MAX_DEPTH && mainGetBit(state->mapGameBit) == 0) {
                mainSetBits(GAMEBIT_WM_SwitchCamActive, 1);
            } else if (mainGetBit(GAMEBIT_WM_SwitchCamActive) != 0) {
                mainSetBits(GAMEBIT_WM_SwitchCamActive, 0);
            }
        } else if (mainGetBit(GAMEBIT_WM_SwitchCamActive) != 0) {
            mainSetBits(GAMEBIT_WM_SwitchCamActive, 0);
        }
    }
    isMoving = 0;
    if (state->holdTimer != 0) {
        targetY = placement->base.posY - PRESSURE_SWITCH_PRESS_DEPTH;
        currentY = obj->anim.localPosY;
        if (currentY < targetY) {
            obj->anim.localPosY = PRESSURE_SWITCH_PRESS_SPEED * timeDelta + currentY;
            if (obj->anim.localPosY > targetY) {
                obj->anim.localPosY = targetY;
            }
            mainSetBits(placement->triggerGameBit, 1);
            if (state->flags.triggerObjectPresent) {
                mainSetBits(state->mapGameBit, 1);
            }
        } else {
            obj->anim.localPosY = -(PRESSURE_SWITCH_RISE_SPEED * timeDelta - currentY);
            if (obj->anim.localPosY < targetY) {
                obj->anim.localPosY = targetY;
                mainSetBits(placement->triggerGameBit, 1);
                mapGameBit = state->mapGameBit;
                if (mapGameBit != -1) {
                    mainSetBits(mapGameBit, 1);
                    if (state->flags.triggerObjectPresent) {
                        state->flags.mapBitLatched = 1;
                    }
                }
            } else {
                isMoving = 1;
            }
        }
    } else if (state->retriggerTimer == 0) {
        obj->anim.localPosY = PRESSURE_SWITCH_RISE_SPEED * timeDelta + obj->anim.localPosY;
        if (obj->anim.localPosY > (verticalOffset = placement->base.posY)) {
            obj->anim.localPosY = verticalOffset;
        } else {
            isMoving = 1;
        }
        mainSetBits(placement->triggerGameBit, 0);
        mapGameBit = state->mapGameBit;
        if (mapGameBit != -1) {
            if (!state->flags.mapBitLatched) {
                mainSetBits(mapGameBit, 0);
            }
        }
    }
    if (isMoving != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_en_treedrum16);
    } else {
        Sfx_StopObjectChannel(obj, PRESSURE_SWITCH_MOVE_SFX_CHANNEL);
    }
    if (state->retriggerTimer != 0) {
        state->retriggerTimer -= framesThisStep;
        if (state->retriggerTimer < 0) {
            state->retriggerTimer = 0;
        }
    }
}

void PressureSwitch_init(GameObject* obj, const PressureSwitchPlacementView* placement) {
    PressureSwitchState* state;
    u32 ident;

    state = obj->extra;
    obj->animEventCallback = PressureSwitch_SeqFn;
    obj->anim.rotX = (s16)((s32)placement->rotationXHighByte << 8);
    state->retriggerTimer = (s16)(placement->retriggerDelay * PRESSURE_SWITCH_RETRIGGER_FRAMES_PER_SEC);
    state->chimeLatch = 0;
    ident = obj->anim.placement->ident;
    if (ident == 0x1F1A) {
        state->mapGameBit = GAMEBIT_WM_SwitchDoorOpen;
    } else if (ident == 0x47293) {
        state->mapGameBit = 0xF46;
    } else {
        state->mapGameBit = -1;
    }
    if (state->mapGameBit != -1) {
        if (mainGetBit(state->mapGameBit) != 0) {
            state->flags.mapBitLatched = 1;
        }
    }
    if (mainGetBit(placement->triggerGameBit) != 0) {
        obj->anim.localPosY = placement->base.posY - PRESSURE_SWITCH_INITIAL_PRESS_DEPTH;
        state->holdTimer = PRESSURE_SWITCH_INITIAL_HOLD_FRAMES;
    }
}

void PressureSwitch_release(void) {
}

void PressureSwitch_initialise(void) {
}

ObjectDescriptor gPressureSwitchObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    PressureSwitch_initialise,
    PressureSwitch_release,
    0,
    (ObjectDescriptorCallback)PressureSwitch_init,
    (ObjectDescriptorCallback)PressureSwitch_update,
    PressureSwitch_hitDetect,
    (ObjectDescriptorCallback)PressureSwitch_render,
    PressureSwitch_free,
    (ObjectDescriptorCallback)PressureSwitch_getObjectTypeId,
    PressureSwitch_getExtraSize,
};
