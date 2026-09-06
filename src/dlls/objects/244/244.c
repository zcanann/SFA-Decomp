/*
 * DoorF4 (DLL 0xF4) - shared game-bit and proximity-controlled door
 * behavior.
 *
 * Gate modes combine messages, game bits, interaction flags, and distance
 * from the door plane to drive animation sequences. Sequence events route
 * partner-door messages, side-specific game bits, effects, and audio.
 */
#include "dlls/objects/244.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/camera.h"
#include "main/gamebits.h"
#include "main/obj_message.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/render_envfx_api.h"
#include "sys/objects.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/obj_list.h"
#include "main/objtype.h"
#include "main/gamebit_ids.h"
#define DOORF4_OBJECT_TYPE_ID 1
#define DOORF4_OBJECT_GROUP   14

#define DOORF4_EXPLODABLE_SEQUENCE_ID 0x7C
#define DOORF4_POWER_DOOR_SEQUENCE_ID 200
#define DOORF4_WARP_DOOR_SEQUENCE_ID  0x151
#define DOORF4_ALT_WARP_SEQUENCE_ID   0x37A
#define DOORF4_LATCH_SEQUENCE_ID      0x13E

#define DOORF4_INBOX_CAPACITY             4
#define DOORF4_INTERACTION_ENABLE_GAMEBIT 0x2C

#define DOORF4_DEFAULT_OPEN_RANGE      200.0f
#define DOORF4_DIRECTIONAL_HALF_DEPTH  30.0f
#define DOORF4_EXPLODABLE_SEARCH_RANGE 320.0f
#define DOORF4_EXPLODABLE_FRONT_DEPTH  160.0f
#define DOORF4_EXPLODABLE_REAR_DEPTH   200.0f
#define DOORF4_WIDE_HALF_DEPTH         60.0f
#define DOORF4_PARTNER_SEARCH_RANGE    1000.0f

#define DOORF4_PI                 3.1415927f
#define DOORF4_BINARY_ANGLE_SCALE 32768.0f

#define DOORF4_OPEN_SFX_ID  830
#define DOORF4_CLOSE_SFX_ID 831

#define DOORF4_RENDER_SCALE          1.0f
#define DOORF4_POWER_DOOR_OPEN_RANGE 100.0f

#define DOORF4_MESSAGE_OPEN          0x30002
#define DOORF4_MESSAGE_CLOSE         0x30003
#define DOORF4_MESSAGE_PARTNER_CLOSE 0x30005
#define DOORF4_MESSAGE_PARTNER_OPEN  0x30006

#define DOORF4_ENVFX_POWERED_OPEN   0x7F
#define DOORF4_ENVFX_UNPOWERED_OPEN 0x7C
#define DOORF4_ENVFX_CLOSE          0xE

enum {
    DOORF4_SEQUENCE_EVENT_OPEN = 1,
    DOORF4_SEQUENCE_EVENT_CLOSE = 2,
    DOORF4_SEQUENCE_EVENT_PLAY_OPEN_SFX = 3,
    DOORF4_SEQUENCE_EVENT_STOP_OPEN_SFX = 4,
    DOORF4_SEQUENCE_EVENT_PLAY_CLOSE_SFX = 5
};

ObjectDescriptor gDoorF4ObjDescriptor = {
    0,                                                /* reserved0 */
    0,                                                /* reserved1 */
    0,                                                /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                 /* slotCountAndFlags */
    (ObjectDescriptorCallback)DoorF4_initialise,      /* initialise */
    (ObjectDescriptorCallback)DoorF4_release,         /* release */
    0,                                                /* slot02 */
    (ObjectDescriptorCallback)DoorF4_init,            /* init */
    (ObjectDescriptorCallback)DoorF4_update,          /* update */
    (ObjectDescriptorCallback)DoorF4_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)DoorF4_render,          /* render */
    (ObjectDescriptorCallback)DoorF4_free,            /* free */
    (ObjectDescriptorCallback)DoorF4_getObjectTypeId, /* getObjectTypeId */
    DoorF4_getExtraSize,                              /* getExtraSize */
};

int DoorF4_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    u32 message;
    int objectCount;
    int objectIndex;
    GameObject* otherObj;
    int openGameBitValue;
    u8 sideGameBitValue;
    int shouldOpen;
    GameObject** objects;
    GameObject* playerObj;
    DoorF4Placement* placement;
    DoorF4State* state;
    Camera* view;
    u8 eventId;
    f32 angle[1];
    f32 distance;
    f32 signedDistance;
    f32 planeNormalZ;
    f32 deltaX;
    f32 deltaZ;
    f32 threshold;
    int index;

    placement = (DoorF4Placement*)obj->anim.placementData;
    state = obj->extra;
    signedDistance = 0.0f;
    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    animUpdate->movementState = 0;
    playerObj = Obj_GetPlayerObject();
    deltaX = playerObj->anim.localPosX - placement->base.posX;
    deltaZ = playerObj->anim.localPosZ - placement->base.posZ;
    distance = sqrtf(deltaX * deltaX + deltaZ * deltaZ);
    if (state->openGameBit == -1) {
        openGameBitValue = 1;
    } else {
        openGameBitValue = mainGetBit(state->openGameBit);
    }
    if (ObjMsg_Peek(obj, &message, 0, 0) != 0) {
        switch (message) {
        case DOORF4_MESSAGE_OPEN:
            state->isOpen = 1;
            break;
        case DOORF4_MESSAGE_CLOSE:
            state->isOpen = 0;
            break;
        }
    }
    shouldOpen = state->isOpen;
    switch (placement->gateMode) {
    case DOORF4_GATE_MODE_GAMEBIT:
        if (openGameBitValue != 0) {
            shouldOpen = 1;
        }
        break;
    case DOORF4_GATE_MODE_PROXIMITY:
        angle[0] = (DOORF4_PI * (placement->yawByte << 8)) / DOORF4_BINARY_ANGLE_SCALE;
        signedDistance = mathSinf(angle[0]);
        planeNormalZ = mathCosf(angle[0]);
        signedDistance = -(placement->base.posX * signedDistance + placement->base.posZ * planeNormalZ) +
                         (signedDistance * playerObj->anim.localPosX + planeNormalZ * playerObj->anim.localPosZ);
        threshold = state->openRange;
        if (distance < threshold && openGameBitValue != 0 && signedDistance < threshold &&
            signedDistance > -threshold) {
            shouldOpen = 1;
        }
        if (shouldOpen != 0 && state->environmentFxActive == 0) {
            if (obj->anim.romDefNo == DOORF4_POWER_DOOR_SEQUENCE_ID) {
                if (mainGetBit(GAMEBIT_CF_PowerOn) != 0) {
                    getEnvfxAct(0, 0, DOORF4_ENVFX_POWERED_OPEN, 0);
                } else {
                    getEnvfxAct(0, 0, DOORF4_ENVFX_UNPOWERED_OPEN, 0);
                }
            }
            state->environmentFxActive = 1;
        } else if (shouldOpen == 0 && state->environmentFxActive == 1) {
            if (obj->anim.romDefNo == DOORF4_POWER_DOOR_SEQUENCE_ID && signedDistance <= 0.0f) {
                getEnvfxAct(0, 0, DOORF4_ENVFX_CLOSE, 0);
            }
            state->environmentFxActive = 0;
        }
        break;
    case DOORF4_GATE_MODE_DIRECTIONAL:
        if (distance < DOORF4_DEFAULT_OPEN_RANGE && openGameBitValue != 0) {
            angle[0] = (DOORF4_PI * (placement->yawByte << 8)) / DOORF4_BINARY_ANGLE_SCALE;
            signedDistance = mathSinf(angle[0]);
            planeNormalZ = mathCosf(angle[0]);
            signedDistance = -(placement->base.posX * signedDistance + placement->base.posZ * planeNormalZ) +
                             (signedDistance * playerObj->anim.localPosX + planeNormalZ * playerObj->anim.localPosZ);
            if (obj->userData2 == 0) {
                if (signedDistance < 0.0f && signedDistance > -DOORF4_DIRECTIONAL_HALF_DEPTH) {
                    shouldOpen = 1;
                }
            } else if (signedDistance < DOORF4_DIRECTIONAL_HALF_DEPTH &&
                       signedDistance > -DOORF4_DIRECTIONAL_HALF_DEPTH) {
                shouldOpen = 1;
            }
        }
        break;
    case DOORF4_GATE_MODE_INTERACTION:
        if (openGameBitValue == 0) {
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_DISABLED) != 0 &&
                mainGetBit(DOORF4_INTERACTION_ENABLE_GAMEBIT) != 0) {
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            }
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                mainSetBits(state->openGameBit, 1);
            }
        } else if (openGameBitValue != 0) {
            shouldOpen = 1;
        }
        break;
    case DOORF4_GATE_MODE_EXPLODABLE:
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if (openGameBitValue != 0) {
            for (index = objectIndex; index < objectCount && shouldOpen == 0; index++) {
                otherObj = objects[index];
                if (otherObj->anim.romDefNo == DOORF4_EXPLODABLE_SEQUENCE_ID) {
                    deltaX = otherObj->anim.localPosX - placement->base.posX;
                    deltaZ = otherObj->anim.localPosZ - placement->base.posZ;
                    if (sqrtf(deltaX * deltaX + deltaZ * deltaZ) < DOORF4_EXPLODABLE_SEARCH_RANGE) {
                        angle[0] = (DOORF4_PI * (placement->yawByte << 8)) / DOORF4_BINARY_ANGLE_SCALE;
                        signedDistance = mathSinf(angle[0]);
                        planeNormalZ = mathCosf(angle[0]);
                        signedDistance =
                            -(placement->base.posX * signedDistance + placement->base.posZ * planeNormalZ) +
                            (signedDistance * otherObj->anim.localPosX + planeNormalZ * otherObj->anim.localPosZ);
                        if (signedDistance < DOORF4_EXPLODABLE_FRONT_DEPTH &&
                            signedDistance > -DOORF4_EXPLODABLE_REAR_DEPTH) {
                            shouldOpen = 1;
                        }
                    }
                }
            }
            if (shouldOpen != 0) {
                if (ObjMsg_Pop(obj, &message, 0, 0) != 0) {
                    switch (message) {
                    case 8:
                    case 9:
                        ObjMsg_SendToObject(otherObj, message, obj, 0);
                        break;
                    }
                }
                if (signedDistance < 0.0f && obj->userData2 == 0) {
                    animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A | OBJSEQ_CONTROL_SET_STATE_LATCH;
                }
            } else if (obj->userData2 == 1) {
                animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_CLEAR_LATCH_A;
            }
        }
        break;
    case DOORF4_GATE_MODE_WIDE_PROXIMITY:
        if (distance < DOORF4_DEFAULT_OPEN_RANGE && openGameBitValue != 0) {
            angle[0] = (DOORF4_PI * (placement->yawByte << 8)) / DOORF4_BINARY_ANGLE_SCALE;
            signedDistance = mathSinf(angle[0]);
            planeNormalZ = mathCosf(angle[0]);
            signedDistance = -(placement->base.posX * signedDistance + placement->base.posZ * planeNormalZ) +
                             (signedDistance * playerObj->anim.localPosX + planeNormalZ * playerObj->anim.localPosZ);
            if (signedDistance < DOORF4_WIDE_HALF_DEPTH && signedDistance > -DOORF4_WIDE_HALF_DEPTH) {
                shouldOpen = 1;
            }
        }
        break;
    case DOORF4_GATE_MODE_POWERED_INTERACTION:
        if (mainGetBit(state->requiredGameBit) != 0 && openGameBitValue == 0) {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                mainSetBits(state->openGameBit, 1);
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                openGameBitValue = 1;
            }
        }
        if (openGameBitValue != 0) {
            shouldOpen = 1;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
        break;
    }
    if (obj->userData2 == 0) {
        if (shouldOpen != 0) {
            animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_B;
        }
    } else if (shouldOpen == 0) {
        animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_CLEAR_LATCH_B;
    }
    obj->userData2 = shouldOpen;
    if ((obj->anim.romDefNo == DOORF4_LATCH_SEQUENCE_ID || obj->anim.romDefNo == DOORF4_WARP_DOOR_SEQUENCE_ID) &&
        state->sequenceLatch != 0) {
        animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_B;
    }
    while (ObjMsg_Pop(obj, &message, 0, 0) != 0) {
    }
    for (index = 0; index < animUpdate->eventCount; index++) {
        eventId = animUpdate->eventIds[index];
        if (eventId != 0) {
            switch (eventId) {
            case DOORF4_SEQUENCE_EVENT_OPEN:
                view = Camera_GetCurrent();
                if (state->planeOffset + (state->planeNormalX * view->x + state->planeNormalZ * view->z) < 0.0f) {
                    if (placement->nearSideGameBit != -1) {
                        sideGameBitValue = mainGetBit(placement->nearSideGameBit);
                        sideGameBitValue ^= (u8)placement->toggleMask;
                        mainSetBits(placement->nearSideGameBit, sideGameBitValue);
                    }
                } else if (placement->farSideGameBit != -1) {
                    sideGameBitValue = mainGetBit(placement->farSideGameBit);
                    sideGameBitValue ^= (u8)(placement->toggleMask >> 8);
                    mainSetBits(placement->farSideGameBit, sideGameBitValue);
                }
                if (signedDistance <= 0.0f) {
                    switch (obj->anim.romDefNo) {
                    case 0x1a2:
                        ObjMsg_SendToNearbyObjects(0x19c, DOORF4_PARTNER_SEARCH_RANGE, 0, obj,
                                                   DOORF4_MESSAGE_PARTNER_OPEN, 0);
                        break;
                    case 0x1ad:
                        ObjMsg_SendToNearbyObjects(0x1ac, DOORF4_PARTNER_SEARCH_RANGE, 0, obj,
                                                   DOORF4_MESSAGE_PARTNER_OPEN, 0);
                        break;
                    case 0x1bb:
                        ObjMsg_SendToNearbyObjects(0x1b9, DOORF4_PARTNER_SEARCH_RANGE, 0, obj,
                                                   DOORF4_MESSAGE_PARTNER_OPEN, 0);
                        break;
                    case 0x1ea:
                        ObjMsg_SendToNearbyObjects(0x1e7, DOORF4_PARTNER_SEARCH_RANGE, 0, obj,
                                                   DOORF4_MESSAGE_PARTNER_OPEN, 0);
                        break;
                    case 0x205:
                        ObjMsg_SendToNearbyObjects(0x202, DOORF4_PARTNER_SEARCH_RANGE, 0, obj,
                                                   DOORF4_MESSAGE_PARTNER_OPEN, 0);
                        break;
                    case 0x21a:
                        ObjMsg_SendToNearbyObjects(0x217, DOORF4_PARTNER_SEARCH_RANGE, 0, obj,
                                                   DOORF4_MESSAGE_PARTNER_OPEN, 0);
                        break;
                    case 0x238:
                        ObjMsg_SendToNearbyObjects(0x233, DOORF4_PARTNER_SEARCH_RANGE, 0, obj,
                                                   DOORF4_MESSAGE_PARTNER_OPEN, 0);
                        break;
                    case 0x23f:
                        ObjMsg_SendToNearbyObjects(0x23c, DOORF4_PARTNER_SEARCH_RANGE, 0, obj,
                                                   DOORF4_MESSAGE_PARTNER_OPEN, 0);
                        break;
                    }
                }
                /* Fall through to play the opening sound. */
            case DOORF4_SEQUENCE_EVENT_PLAY_OPEN_SFX:
                if (state->openSfxId != 0) {
                    Sfx_PlayFromObject(obj, state->openSfxId);
                }
                break;
            case DOORF4_SEQUENCE_EVENT_STOP_OPEN_SFX:
                if (state->openSfxId != 0 && Sfx_IsPlayingFromObject(obj, state->openSfxId) != 0) {
                    Sfx_StopFromObject(obj, state->openSfxId);
                }
                break;
            case DOORF4_SEQUENCE_EVENT_PLAY_CLOSE_SFX:
                if (state->closeSfxId != 0 && mainGetBit(GAMEBIT_SHRINE_MUSIC_LOCK) == 0) {
                    Sfx_PlayFromObject(obj, state->closeSfxId);
                }
                break;
            case DOORF4_SEQUENCE_EVENT_CLOSE:
                view = Camera_GetCurrent();
                if (state->planeOffset + (state->planeNormalX * view->x + state->planeNormalZ * view->z) < 0.0f) {
                    if (placement->nearSideGameBit != -1) {
                        sideGameBitValue = mainGetBit(placement->nearSideGameBit);
                        sideGameBitValue ^= (u8)placement->toggleMask;
                        mainSetBits(placement->nearSideGameBit, sideGameBitValue);
                    }
                } else if (placement->farSideGameBit != -1) {
                    sideGameBitValue = mainGetBit(placement->farSideGameBit);
                    sideGameBitValue ^= (u8)(placement->toggleMask >> 8);
                    mainSetBits(placement->farSideGameBit, sideGameBitValue);
                }
                switch (obj->anim.romDefNo) {
                case 0x1a2:
                    ObjMsg_SendToNearbyObjects(0x19c, DOORF4_PARTNER_SEARCH_RANGE, 0, obj, DOORF4_MESSAGE_PARTNER_CLOSE,
                                               0);
                    break;
                case 0x1ad:
                    ObjMsg_SendToNearbyObjects(0x1ac, DOORF4_PARTNER_SEARCH_RANGE, 0, obj, DOORF4_MESSAGE_PARTNER_CLOSE,
                                               0);
                    break;
                case 0x1bb:
                    ObjMsg_SendToNearbyObjects(0x1b9, DOORF4_PARTNER_SEARCH_RANGE, 0, obj, DOORF4_MESSAGE_PARTNER_CLOSE,
                                               0);
                    break;
                case 0x1ea:
                    ObjMsg_SendToNearbyObjects(0x1e7, DOORF4_PARTNER_SEARCH_RANGE, 0, obj, DOORF4_MESSAGE_PARTNER_CLOSE,
                                               0);
                    break;
                case 0x205:
                    ObjMsg_SendToNearbyObjects(0x202, DOORF4_PARTNER_SEARCH_RANGE, 0, obj, DOORF4_MESSAGE_PARTNER_CLOSE,
                                               0);
                    break;
                case 0x21a:
                    ObjMsg_SendToNearbyObjects(0x217, DOORF4_PARTNER_SEARCH_RANGE, 0, obj, DOORF4_MESSAGE_PARTNER_CLOSE,
                                               0);
                    break;
                case 0x238:
                    ObjMsg_SendToNearbyObjects(0x233, DOORF4_PARTNER_SEARCH_RANGE, 0, obj, DOORF4_MESSAGE_PARTNER_CLOSE,
                                               0);
                    break;
                case 0x23f:
                    ObjMsg_SendToNearbyObjects(0x23c, DOORF4_PARTNER_SEARCH_RANGE, 0, obj, DOORF4_MESSAGE_PARTNER_CLOSE,
                                               0);
                    break;
                }
                break;
            }
            animUpdate->eventIds[index] = 0;
        }
    }
    if (obj->userData1 != 0) {
        obj->userData1 = 0;
        return 3;
    }
    return 0;
}

int DoorF4_getExtraSize(void) {
    return sizeof(DoorF4State);
}

int DoorF4_getObjectTypeId(void) {
    return DOORF4_OBJECT_TYPE_ID;
}

void DoorF4_free(GameObject* obj) {
    DoorF4State* state = obj->extra;
    if (state->openSfxId != 0) {
        if (Sfx_IsPlayingFromObject(obj, state->openSfxId) != 0) {
            Sfx_StopFromObject(obj, state->openSfxId);
        }
    }
    objFreeObjectType(obj, DOORF4_OBJECT_GROUP);
}

void DoorF4_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, DOORF4_RENDER_SCALE);
    }
}

void DoorF4_hitDetect(void) {
}

void DoorF4_update(GameObject* obj) {
    DoorF4State* state = obj->extra;
    state->sequenceLatch = 0;
    if (obj->userData1 == 0) {
        DoorF4Placement* placement = (DoorF4Placement*)obj->anim.placementData;
        s16 sequenceId;
        obj->anim.localPosX = placement->base.posX;
        obj->anim.localPosY = placement->base.posY;
        obj->anim.localPosZ = placement->base.posZ;
        obj->anim.rotX = placement->yawByte << 8;
        sequenceId = obj->anim.romDefNo;
        if (sequenceId == DOORF4_WARP_DOOR_SEQUENCE_ID) {
            if (mainGetBit(state->openGameBit) != 0) {
                (*gObjectTriggerInterface)->preempt((int)obj, 0x75);
                state->sequenceLatch = 1;
            }
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        } else if (sequenceId == DOORF4_ALT_WARP_SEQUENCE_ID) {
            if (mainGetBit(state->openGameBit) != 0) {
                (*gObjectTriggerInterface)->preempt((int)obj, 0x8a);
                state->sequenceLatch = 1;
            }
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        } else {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        obj->userData1 = 1;
    }
}

void DoorF4_init(GameObject* obj, DoorF4Placement* placement) {
    DoorF4State* state = obj->extra;
    s16 sequenceId;

    ObjMsg_AllocQueue(obj, DOORF4_INBOX_CAPACITY);
    obj->anim.rotX = placement->yawByte << 8;
    obj->animEventCallback = DoorF4_SeqFn;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    state->openGameBit = placement->openGameBit;
    state->nearSideGameBit = placement->nearSideGameBit;
    state->openRange = DOORF4_DEFAULT_OPEN_RANGE;

    sequenceId = obj->anim.romDefNo;
    switch (sequenceId) {
    case 193:
    case 196:
        state->requiredGameBit = 68;
        break;
    case 283:
    case 284:
        state->requiredGameBit = 152;
        break;
    case 318:
    case 890:
        state->openSfxId = DOORF4_OPEN_SFX_ID;
        state->closeSfxId = DOORF4_CLOSE_SFX_ID;
        break;
    case DOORF4_POWER_DOOR_SEQUENCE_ID:
        state->openRange = DOORF4_POWER_DOOR_OPEN_RANGE;
        break;
    default:
        state->requiredGameBit = -1;
    }

    objAddObjectType(obj, DOORF4_OBJECT_GROUP);

    state->planeNormalX = mathSinf(DOORF4_PI * obj->anim.rotX / DOORF4_BINARY_ANGLE_SCALE);
    state->planeNormalZ = mathCosf(DOORF4_PI * obj->anim.rotX / DOORF4_BINARY_ANGLE_SCALE);
    state->planeOffset = -(state->planeNormalX * obj->anim.localPosX + state->planeNormalZ * obj->anim.localPosZ);
}

void DoorF4_release(void) {
}

void DoorF4_initialise(void) {
}
