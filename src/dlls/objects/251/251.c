/*
 * DLL 0xFB - weight-activated pressure switches.
 *
 * The pad tracks nearby objects, animates toward its pressed height, mirrors a
 * game bit and texture state, and can drive a linked Tricky interaction.
 */
#include "dlls/objects/251.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dlls/objects/196_Tricky.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/objtexture.h"
#include "main/objtype.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/dll/player_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/objseq.h"

#define PRESSURESWITCHFB_PARTFX_ID                      0x7C3
#define PRESSURESWITCHFB_ANIM_COMMAND_IDLE              0
#define PRESSURESWITCHFB_ANIM_COMMAND_CAPTURE_POSITIONS 1
#define PRESSURESWITCHFB_ANIM_COMMAND_RESET             2

#define PRESSURESWITCHFB_TRACKED_OBJECT_COUNT 10
#define PRESSURESWITCHFB_TRACKED_OBJECT_BATCH 5
#define PRESSURESWITCHFB_CONTACT_FRAMES       5

#define PRESSURESWITCHFB_TRACKED_SEQ_ID_A 0x754
#define PRESSURESWITCHFB_TRACKED_SEQ_ID_B 0x6D

#define PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET   0x04
#define PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET 0x2C

#define PRESSURESWITCHFB_OBJECT_GROUP        0x53
#define PRESSURESWITCHFB_TARGET_OBJECT_GROUP 5

#define PRESSURESWITCHFB_PRESSED_TEXTURE_ID    0x100
#define PRESSURESWITCHFB_DISABLED_TEXTURE_ID   0
#define PRESSURESWITCHFB_NO_GAME_BIT           -1
#define PRESSURESWITCHFB_TRACKED_POSITION_MASK 0xFF

#define PRESSURESWITCHFB_SEQ_ID_LINK_SNOWPR 0x019F
#define PRESSURESWITCHFB_SEQ_ID_SH_PRESSURE 0x026C
#define PRESSURESWITCHFB_SEQ_ID_LINK_UNDERW 0x0274
#define PRESSURESWITCHFB_SEQ_ID_CC_PRESSURE 0x0545
#define PRESSURESWITCHFB_SEQ_ID_GROUNDQUAKE 0x077B

#define PRESSURESWITCHFB_TRACKED_CLASS_PLAYER 1
#define PRESSURESWITCHFB_TRACKED_CLASS_TRICKY 2

#define PRESSURESWITCHFB_TARGET_SEARCH_RADIUS 40.0f
#define PRESSURESWITCHFB_PARTICLE_DISTANCE    200.0f
#define PRESSURESWITCHFB_DEFAULT_VELOCITY     0.125f
#define PRESSURESWITCHFB_INITIAL_CONTACT_TIME 30

#define PRESSURESWITCHFB_PARTICLE_COUNT    3
#define PRESSURESWITCHFB_PARTICLE_FLAGS    2
#define PRESSURESWITCHFB_PARTICLE_SCALE    1.5f
#define PRESSURESWITCHFB_PARTICLE_Y_OFFSET 4.5f
#define PRESSURESWITCHFB_PARTICLE_ARG2     10
#define PRESSURESWITCHFB_PARTICLE_ARG3     0x12

#define PRESSURESWITCHFB_MOVEMENT_SFX_CHANNEL 8

int PressureSwitchFB_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    s16 sequenceId;
    PressureSwitchFBPlacement* placement;
    GameObject* trackedObject;
    u32 trackedObjectOffset;
    PressureSwitchFBState* stateAddress;
    int positionAddress;
    u8 trackedIndex;

    stateAddress = obj->extra;
    placement = (PressureSwitchFBPlacement*)obj->anim.placementData;
    if (animUpdate->curEventId == PRESSURESWITCHFB_ANIM_COMMAND_CAPTURE_POSITIONS) {
        for (trackedIndex = 0; trackedIndex < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT; trackedIndex++) {
            trackedObjectOffset = (u32)trackedIndex * 4 + PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET;
            trackedObject = (GameObject*)*(u32*)((int)stateAddress + trackedObjectOffset);
            if (trackedObject != 0) {
                ((PressureSwitchFBState*)(positionAddress = (int)stateAddress + (u32)trackedIndex * 8))
                    ->trackedPositions[0]
                    .x = trackedObject->anim.localPosX;
                ((PressureSwitchFBState*)positionAddress)->trackedPositions[0].z =
                    ((GameObject*)*(int*)((int)stateAddress + trackedObjectOffset))->anim.localPosZ;
            }
        }
        animUpdate->curEventId = PRESSURESWITCHFB_ANIM_COMMAND_IDLE;
    } else if (animUpdate->curEventId == PRESSURESWITCHFB_ANIM_COMMAND_RESET) {
        for (trackedIndex = 0; trackedIndex < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT;
             trackedIndex += PRESSURESWITCHFB_TRACKED_OBJECT_BATCH) {
            *(int*)(positionAddress =
                        (int)stateAddress + trackedIndex * 4 + PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET) = 0;
            *(int*)(positionAddress + 0x4) = 0;
            *(int*)(positionAddress + 0x8) = 0;
            *(int*)(positionAddress + 0xC) = 0;
            *(int*)(positionAddress + 0x10) = 0;
        }
        /* Retail performs both horizontal reset stores through localPosZ. */
        obj->anim.localPosZ = placement->base.posX;
        obj->anim.localPosY = stateAddress->targetPosY;
        obj->anim.localPosZ = placement->base.posZ;
        mainSetBits(placement->pressedGameBit, 0);
        animUpdate->curEventId = PRESSURESWITCHFB_ANIM_COMMAND_IDLE;
    }
    sequenceId = obj->anim.romDefNo;
    if ((((sequenceId != PRESSURESWITCHFB_SEQ_ID_LINK_SNOWPR) && (sequenceId != PRESSURESWITCHFB_SEQ_ID_SH_PRESSURE)) &&
         (sequenceId != PRESSURESWITCHFB_SEQ_ID_LINK_UNDERW)) &&
        (sequenceId != PRESSURESWITCHFB_SEQ_ID_CC_PRESSURE)) {
        stateAddress->targetPosY = obj->anim.localPosY;
    }
    return 0;
}

int PressureSwitchFB_getExtraSize(void) {
    return sizeof(PressureSwitchFBState);
}

void PressureSwitchFB_free(GameObject* obj) {
    objFreeObjectType(obj, PRESSURESWITCHFB_OBJECT_GROUP);
}

static inline int PressureSwitchFB_scanTrackedSlots(PressureSwitchFBState* state) {
    GameObject* trackedObject;
    u8 slotIndex;
    int foundTrackedObject;

    foundTrackedObject = 0;
    for (slotIndex = 0; slotIndex < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT; slotIndex++) {
        trackedObject = state->trackedObjects[slotIndex];
        if (trackedObject != NULL) {
            if ((state->trackedPositions[slotIndex].x == trackedObject->anim.localPosX) &&
                (state->trackedPositions[slotIndex].z == trackedObject->anim.localPosZ)) {
                foundTrackedObject = 1;
            } else {
                state->trackedObjects[slotIndex] = NULL;
            }
        }
    }
    return foundTrackedObject;
}

static inline void PressureSwitchFB_addTrackedObject(GameObject* obj, GameObject* trackedObject) {
    PressureSwitchFBState* state = obj->extra;
    u8 trackedIndex;

    trackedIndex = 0;
    if (state->flags.playerOnly != 0) {
        if (trackedObject != Obj_GetPlayerObject()) {
            return;
        }
    }
    while ((state->trackedObjects[trackedIndex] != NULL) &&
           (trackedIndex != PRESSURESWITCHFB_TRACKED_OBJECT_COUNT - 1)) {
        trackedIndex++;
    }
    state->trackedObjects[trackedIndex] = trackedObject;
    state->trackedPositions[trackedIndex].x = trackedObject->anim.localPosX;
    state->trackedPositions[trackedIndex].z = trackedObject->anim.localPosZ;
}

void PressureSwitchFB_update(GameObject* obj) {
    int foundTrackedObject;
    GameObject* nearbyObject;
    int isMoving;
    PressureSwitchFBPlacement* placement;
    PressureSwitchFBState* state;
    int i;
    GameObject* scratch;
    int effectIndex;
    int isTrackedType;
    ObjTextureRuntimeSlot* texture;
    f32 currentY;
    f32 targetY;
    u32 nearestTarget;
    GameObject* trickyObj;
    f32 searchRadius;
    PartFxSpawnParams effectParams;

    placement = (PressureSwitchFBPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (state->flags.active != 0) {
        if (state->flags.released == 0) {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        } else {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        }
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    if ((placement->enableGameBit == PRESSURESWITCHFB_NO_GAME_BIT) || (mainGetBit(placement->enableGameBit) != 0)) {
        if (--state->contactTimer < 0) {
            state->contactTimer = 0;
        }
        searchRadius = PRESSURESWITCHFB_TARGET_SEARCH_RADIUS;
        nearestTarget = (u32)objGetNearestTypeTo(PRESSURESWITCHFB_TARGET_OBJECT_GROUP, obj, &searchRadius);
        if (nearestTarget != 0) {
            state->contactTimer = PRESSURESWITCHFB_CONTACT_FRAMES;
        }
        if (obj->anim.hitboxTransformState->contactObjectCount > 0) {
            for (i = 0; i < obj->anim.hitboxTransformState->contactObjectCount; i++) {
                nearbyObject = obj->anim.hitboxTransformState->contactObjects[i];
                if ((nearbyObject->anim.classId == PRESSURESWITCHFB_TRACKED_CLASS_PLAYER) ||
                    (nearbyObject->anim.classId == PRESSURESWITCHFB_TRACKED_CLASS_TRICKY) ||
                    (nearbyObject->anim.romDefNo == PRESSURESWITCHFB_TRACKED_SEQ_ID_A) ||
                    (nearbyObject->anim.romDefNo == PRESSURESWITCHFB_TRACKED_SEQ_ID_B)) {
                    isTrackedType = 1;
                } else {
                    isTrackedType = 0;
                }
                if (isTrackedType && ((int)nearbyObject != nearestTarget)) {
                    if (nearbyObject->anim.localPosY - obj->anim.localPosY > (f32)(u32)placement->triggerHeight) {
                        PressureSwitchFB_addTrackedObject(obj, nearbyObject);
                    }
                }
            }
        }
        foundTrackedObject = PressureSwitchFB_scanTrackedSlots(obj->extra);
        if (foundTrackedObject & PRESSURESWITCHFB_TRACKED_POSITION_MASK) {
            state->contactTimer = PRESSURESWITCHFB_CONTACT_FRAMES;
        }
        isMoving = 0;
        if ((state->contactTimer != 0) && (state->flags.latched == 0)) {
            if (state->flags.active != 0) {
                if (playerIsQuakeShockwaveActive(Obj_GetPlayerObject()) != 0) {
                    state->flags.released = 0;
                }
            }
            if (state->flags.released == 0) {
                targetY = state->targetPosY - (f32)(u32)placement->pressDepth;
                currentY = obj->anim.localPosY;
                if (currentY < targetY) {
                    obj->anim.localPosY = state->velocityY * timeDelta + currentY;
                    if (obj->anim.localPosY > targetY) {
                        obj->anim.localPosY = targetY;
                    }
                    mainSetBits(placement->pressedGameBit, 1);
                    if (state->flags.active != 0) {
                        texture = objFindTexture(obj, 0, 0);
                        if (texture != NULL) {
                            texture->textureId = PRESSURESWITCHFB_PRESSED_TEXTURE_ID;
                        }
                        state->flags.latched = 1;
                    }
                } else {
                    obj->anim.localPosY = -(state->velocityY * timeDelta - currentY);
                    if (obj->anim.localPosY < targetY) {
                        obj->anim.localPosY = targetY;
                        mainSetBits(placement->pressedGameBit, 1);
                        if (state->flags.active != 0) {
                            texture = objFindTexture(obj, 0, 0);
                            if (texture != NULL) {
                                texture->textureId = PRESSURESWITCHFB_PRESSED_TEXTURE_ID;
                            }
                            state->flags.latched = 1;
                        }
                    } else {
                        isMoving = 1;
                    }
                }
            } else {
                obj->anim.localPosY = state->velocityY * timeDelta + obj->anim.localPosY;
                if (obj->anim.localPosY > state->targetPosY) {
                    obj->anim.localPosY = state->targetPosY;
                } else {
                    isMoving = 1;
                }
            }
        } else {
            if (state->flags.latched == 0) {
                currentY = obj->anim.localPosY;
                if (currentY < state->targetPosY) {
                    obj->anim.localPosY = state->velocityY * timeDelta + currentY;
                    if (obj->anim.localPosY > state->targetPosY) {
                        obj->anim.localPosY = state->targetPosY;
                        mainSetBits(placement->pressedGameBit, 0);
                    } else {
                        isMoving = 1;
                    }
                }
            } else {
                if (mainGetBit(placement->pressedGameBit) == 0) {
                    texture = objFindTexture(obj, 0, 0);
                    if (texture != NULL) {
                        texture->textureId = PRESSURESWITCHFB_DISABLED_TEXTURE_ID;
                    }
                    state->flags.latched = 0;
                    state->flags.released = 1;
                }
            }
        }
        if (((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) && (state->flags.latched == 0) &&
            (state->flags.active != 0)) {
            scratch = Obj_GetPlayerObject();
            if (Vec_distance(&obj->anim.worldPosX, &scratch->anim.worldPosX) < PRESSURESWITCHFB_PARTICLE_DISTANCE) {
                effectParams.posX = 0.0f;
                effectParams.posY = PRESSURESWITCHFB_PARTICLE_Y_OFFSET;
                effectParams.posZ = 0.0f;
                effectParams.scale = PRESSURESWITCHFB_PARTICLE_SCALE;
                effectParams.arg3 = PRESSURESWITCHFB_PARTICLE_ARG3;
                effectParams.arg2 = PRESSURESWITCHFB_PARTICLE_ARG2;
                effectIndex = 0;
                do {
                    (*gPartfxInterface)
                        ->spawnObject((void*)obj, PRESSURESWITCHFB_PARTFX_ID, &effectParams,
                                      PRESSURESWITCHFB_PARTICLE_FLAGS, -1, NULL);
                    effectIndex++;
                } while (effectIndex < PRESSURESWITCHFB_PARTICLE_COUNT);
            }
        }
        if ((s8)isMoving != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_en_firlp6);
        } else {
            Sfx_StopObjectChannel(obj, PRESSURESWITCHFB_MOVEMENT_SFX_CHANNEL);
        }
        if (((placement->drivesTricky != 0) && ((trickyObj = (GameObject*)getTrickyObject()) != NULL)) &&
            (mainGetBit(placement->pressedGameBit) == 0)) {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
                TRICKY_INTERFACE(trickyObj)->sideCommandEnable(trickyObj, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                                               TRICKY_COMMAND_TYPE_STAY);
            }
        }
    }
}

void PressureSwitchFB_init(GameObject* obj, PressureSwitchFBPlacement* placement) {
    ObjAnimComponent* anim;
    PressureSwitchFBState* state;
    ObjTextureRuntimeSlot* texture;
    f32 defaultVelocity;
    PressureSwitchFBFlags* flags;

    anim = (ObjAnimComponent*)obj;
    state = obj->extra;
    flags = &state->flags;
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    anim->bankIndex = placement->modelBankIndex;
    if (anim->bankIndex >= anim->modelInstance->modelCount) {
        anim->bankIndex = 0;
    }
    defaultVelocity = PRESSURESWITCHFB_DEFAULT_VELOCITY;
    state->velocityY = defaultVelocity;
    if (obj->anim.romDefNo == PRESSURESWITCHFB_SEQ_ID_GROUNDQUAKE) {
        flags->active = 1;
        flags->playerOnly = 1;
        flags->released = 1;
        state->velocityY = defaultVelocity;
    }
    state->targetPosY = placement->base.posY;
    if (mainGetBit(placement->pressedGameBit) != 0) {
        s16 sequenceId;
        obj->anim.localPosY = state->targetPosY - (f32)(u32)placement->pressDepth;
        state->contactTimer = PRESSURESWITCHFB_INITIAL_CONTACT_TIME;
        flags->released = 0;
        sequenceId = obj->anim.romDefNo;
        if (sequenceId != PRESSURESWITCHFB_SEQ_ID_LINK_SNOWPR) {
            if (sequenceId != PRESSURESWITCHFB_SEQ_ID_SH_PRESSURE) {
                if (sequenceId != PRESSURESWITCHFB_SEQ_ID_LINK_UNDERW) {
                    if (sequenceId != PRESSURESWITCHFB_SEQ_ID_CC_PRESSURE) {
                        flags->latched = 1;
                    }
                }
            }
        }
        if (flags->active) {
            texture = objFindTexture(obj, 0, 0);
            if (texture != NULL) {
                texture->textureId = PRESSURESWITCHFB_PRESSED_TEXTURE_ID;
            }
        }
    }
    objAddObjectType(obj, PRESSURESWITCHFB_OBJECT_GROUP);
    state->trackedObjects[0] = NULL;
    state->trackedObjects[1] = NULL;
    state->trackedObjects[2] = NULL;
    state->trackedObjects[3] = NULL;
    state->trackedObjects[4] = NULL;
    state->trackedObjects[5] = NULL;
    state->trackedObjects[6] = NULL;
    state->trackedObjects[7] = NULL;
    state->trackedObjects[8] = NULL;
    state->trackedObjects[9] = NULL;
    obj->animEventCallback = PressureSwitchFB_animEventCallback;
}

ObjectDescriptor gPressureSwitchFBObjDescriptor = {
    0,                                                 /* reserved0 */
    0,                                                 /* reserved1 */
    0,                                                 /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                  /* slotCountAndFlags */
    0,                                                 /* initialise */
    0,                                                 /* release */
    0,                                                 /* slot02 */
    (ObjectDescriptorCallback)PressureSwitchFB_init,   /* init */
    (ObjectDescriptorCallback)PressureSwitchFB_update, /* update */
    0,                                                 /* hitDetect */
    0,                                                 /* render */
    (ObjectDescriptorCallback)PressureSwitchFB_free,   /* free */
    0,                                                 /* getObjectTypeId */
    PressureSwitchFB_getExtraSize,                     /* getExtraSize */
};
