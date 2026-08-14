/* Wind-lift controller shared by CFWindLift and CFTreasWind. */

#include "dlls/objects/329.h"

#include "main/audio/music_trigger_ids.h"
#include "main/dll/player_motion.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objtype.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/audio/music_api.h"
#include "main/maketex_sequence_api.h"
#include "main/obj_message.h"

#define CFWINDLIFT_OBJECT_GROUP     0x49
#define WINDLIFT_RIDER_OBJECT_GROUP 0x16

#define WINDLIFT_HEIGHT_BYTE_SCALE   4.0f
#define WINDLIFT_DEFAULT_HEIGHT      90.0f
#define WINDLIFT_DEFAULT_DURATION    100
#define WINDLIFT_SPIN_UP_FRAMES      60
#define WINDLIFT_OBJECT_TYPE_ID      0
#define WINDLIFT_LONG_DURATION       10
#define WINDLIFT_ALPHA_MAX           0xFF
#define WINDLIFT_RIDER_ENTER_MESSAGE 0x0F
#define WINDLIFT_RIDER_EXIT_MESSAGE  0x10
#define WINDLIFT_SLOT_SEARCH_END     2000

#define WINDLIFT_DURATION_ENTRY_COUNT        4
#define WINDLIFT_ENABLE_GAME_BIT_ENTRY_COUNT 3

typedef enum WindLiftSlotFlag {
    WINDLIFT_SLOT_FLAG_RISING = 0x01,
    WINDLIFT_SLOT_FLAG_PENDING = 0x02,
    WINDLIFT_SLOT_FLAG_PULL_UP = 0x04,
    WINDLIFT_SLOT_FLAG_PULL_DOWN = 0x08,
    WINDLIFT_SLOT_FLAG_HOLD = 0x20,
    WINDLIFT_SLOT_FLAG_RELEASE = 0x40,
    WINDLIFT_SLOT_FLAG_LATCH = 0x80,
} WindLiftSlotFlag;

#define WINDLIFT_SLOT_DIRECTION_FLAGS 0x0E
#define WINDLIFT_SLOT_PHASE_FLAGS     0xE0
#define WINDLIFT_SLOT_RESET_FLAGS     0xF1

int gWindLiftDurationTable[WINDLIFT_DURATION_ENTRY_COUNT][2] = {
    {0x58, 1},
    {0x59, 2},
    {0x5A, 3},
    {0xAD7, 4},
};

int gWindLiftEnableGameBitTable[WINDLIFT_ENABLE_GAME_BIT_ENTRY_COUNT][2] = {
    {0xA94, 0x95},
    {0xA98, 0x95},
    {0xA99, 0x95},
};

static void windLift_resetSlot(WindLiftSlot* slot) {
    slot->phaseFlags = 0;
    slot->phaseFlags &= ~WINDLIFT_SLOT_RESET_FLAGS;
    slot->unknown04 = 0.1f;
    slot->riseSpeed = 0.0f;
    slot->speedDelta = 0.0f;
    slot->riderObject = 0;
    slot->oscillationCounter = 0;
}

/* Update one rider's lift state and vertical motion. */
void windLift_updateRider(GameObject* obj, GameObject* rider, WindLiftSlot* slot, f32 pullStrength, int riderGameBit,
                          int isPlayer, u32 duration, f32 radius) {
    GameObject* player;
    f32 liftLimit;
    f32 riseFactor;
    f32 remainingDistance;
    f32 riseSpeed;
    f32 speedThreshold;
    f32 heightOffset;
    f32 horizontalDistance;
    f32 forceFactor;
    f32 accelerationScale;
    u8 initialFlags;
    u8 phaseFlags;
    int directionFlags;
    player = Obj_GetPlayerObject();
    heightOffset = rider->anim.localPosY - obj->anim.localPosY;
    if (heightOffset < 0.0f) {
        return;
    }
    horizontalDistance = Vec_xzDistance(&rider->anim.worldPosX, &obj->anim.worldPosX);
    if (horizontalDistance > 10.0f + radius && (slot->phaseFlags & WINDLIFT_SLOT_PHASE_FLAGS) == 0) {
        return;
    }
    initialFlags = slot->phaseFlags;
    if ((initialFlags & WINDLIFT_SLOT_FLAG_LATCH) != 0 && riderGameBit != 0) {
        return;
    }
    if (horizontalDistance < radius) {
        if ((initialFlags & WINDLIFT_SLOT_PHASE_FLAGS) == 0 || (initialFlags & WINDLIFT_SLOT_FLAG_LATCH) != 0) {
            if (riderGameBit != 0 && (!initialFlags & WINDLIFT_SLOT_FLAG_LATCH) != 0 && heightOffset < 20.0f) {
                slot->phaseFlags |= WINDLIFT_SLOT_FLAG_LATCH;
                return;
            }
            if ((initialFlags & WINDLIFT_SLOT_FLAG_PENDING) != 0) {
                if (heightOffset / pullStrength > 0.8f) {
                    slot->phaseFlags |= WINDLIFT_SLOT_FLAG_PULL_UP;
                    slot->phaseFlags &= ~WINDLIFT_SLOT_FLAG_PULL_DOWN;
                } else {
                    slot->phaseFlags |= WINDLIFT_SLOT_FLAG_PULL_DOWN;
                    slot->phaseFlags &= ~WINDLIFT_SLOT_FLAG_PULL_UP;
                }
                slot->phaseFlags &= ~WINDLIFT_SLOT_FLAG_PENDING;
            }
            if (riderGameBit == 0) {
                slot->phaseFlags |= WINDLIFT_SLOT_FLAG_RELEASE;
                slot->phaseFlags &= ~WINDLIFT_SLOT_FLAG_HOLD;
                ObjMsg_SendToObject(rider, WINDLIFT_RIDER_ENTER_MESSAGE, obj,
                                    (((slot->phaseFlags & WINDLIFT_SLOT_PHASE_FLAGS) >> 4) << 8) | duration);
                slot->phaseFlags &= ~WINDLIFT_SLOT_FLAG_LATCH;
            } else {
                if (heightOffset > 30.0f) {
                    ObjMsg_SendToObject(rider, WINDLIFT_RIDER_ENTER_MESSAGE, obj,
                                        (((slot->phaseFlags & WINDLIFT_SLOT_PHASE_FLAGS) >> 4) << 8) | duration);
                }
                slot->phaseFlags |= WINDLIFT_SLOT_FLAG_HOLD;
                slot->phaseFlags &= ~WINDLIFT_SLOT_FLAG_RELEASE;
            }
        }
        accelerationScale = 0.324f;
        phaseFlags = slot->phaseFlags;
        directionFlags = phaseFlags & WINDLIFT_SLOT_DIRECTION_FLAGS;
        if (directionFlags != 0 && (phaseFlags & WINDLIFT_SLOT_FLAG_PULL_DOWN) != 0 && riderGameBit == 0) {
            pullStrength *= 0.6f;
        }
        pullStrength *= 0.6f;
        if (pullStrength <= 10.0f) {
            return;
        }
        if (heightOffset < 3.0f) {
            heightOffset = 3.0f;
        }
        if (riderGameBit == 0) {
            liftLimit = pullStrength - (pullStrength / 50.0f) * (slot->riseSpeed * (slot->riseSpeed * slot->riseSpeed));
            if (heightOffset > liftLimit) {
                riseFactor = 0.0f;
            } else {
                remainingDistance = liftLimit - heightOffset;
                if (remainingDistance > 20.0f) {
                    riseFactor = 1.0f;
                } else {
                    riseFactor = remainingDistance / 20.0f;
                }
            }
            forceFactor = riseFactor;
            slot->phaseFlags |= WINDLIFT_SLOT_FLAG_RISING;
            if (((slot->riseSpeed < -0.2f && slot->oscillationCounter % 2 != 0) ||
                 (slot->riseSpeed > 0.2f && slot->oscillationCounter % 2 == 0)) &&
                (slot->phaseFlags & WINDLIFT_SLOT_FLAG_PULL_DOWN) != 0) {
                if (slot->oscillationCounter++ > 2) {
                    slot->phaseFlags &= ~WINDLIFT_SLOT_FLAG_PULL_DOWN;
                    slot->phaseFlags |= WINDLIFT_SLOT_FLAG_PULL_UP;
                }
            }
        } else {
            riseSpeed = slot->riseSpeed;
            if (directionFlags != 0) {
                speedThreshold = 0.1f;
            } else {
                speedThreshold = 0.5f;
            }
            if (riseSpeed > speedThreshold) {
                slot->oscillationCounter = 1;
            }
            accelerationScale *= 1.5f;
            if (slot->oscillationCounter == 0) {
                if ((slot->phaseFlags & WINDLIFT_SLOT_DIRECTION_FLAGS) != 0) {
                    forceFactor = 1.0f - heightOffset / (1.55f * pullStrength);
                } else {
                    forceFactor = 1.0f - heightOffset / (0.9f * pullStrength);
                }
                if (forceFactor < 0.0f) {
                    forceFactor = 0.0f;
                }
                forceFactor = forceFactor * forceFactor;
            } else {
                forceFactor = 0.01f;
            }
        }
        slot->speedDelta = accelerationScale * forceFactor - 0.18f;
        slot->riseSpeed = slot->riseSpeed + slot->speedDelta;
        if (slot->riseSpeed > 8.0f) {
            slot->riseSpeed = 8.0f;
        }
        if (slot->riseSpeed == 0.0f) {
            slot->riseSpeed = -0.001f;
        }
        if (heightOffset < 20.0f && riderGameBit != 0) {
            slot->riseSpeed = 0.0f;
            slot->oscillationCounter = 0;
            ObjMsg_SendToObject(rider, WINDLIFT_RIDER_EXIT_MESSAGE, obj, riderGameBit);
            slot->phaseFlags |= WINDLIFT_SLOT_FLAG_LATCH;
            if (isPlayer != 0) {
                player->anim.velocityY = 0.0f;
            }
        }
        if (isPlayer != 0) {
            Player_SetLiftVelocityY(rider, slot->riseSpeed);
        } else {
            rider->anim.localPosY = slot->riseSpeed * timeDelta + rider->anim.localPosY;
            rider->anim.velocityY = slot->riseSpeed * timeDelta;
        }
    } else {
        if (isPlayer != 0) {
            Player_SetLiftVelocityY(rider, 0.0f);
        }
        if (isPlayer == 0) {
            ObjMsg_SendToObject(rider, WINDLIFT_RIDER_EXIT_MESSAGE, obj, riderGameBit);
            slot->phaseFlags &= ~WINDLIFT_SLOT_RESET_FLAGS;
            slot->riseSpeed = 0.0f;
            slot->oscillationCounter = 0;
        }
    }
}

int windLift_getExtraSize(void) {
    return sizeof(WindLiftState);
}

int windLift_getObjectTypeId(void) {
    return WINDLIFT_OBJECT_TYPE_ID;
}

void windLift_free(GameObject* obj) {
    GameObject* player = Obj_GetPlayerObject();
    if (player == NULL || Player_GetLiftVelocityY(player) == 0.0f) {
        Music_Trigger(MUSICTRIG_DIM_Cavern, 0);
    }
    objFreeObjectType(obj, CFWINDLIFT_OBJECT_GROUP);
}

void windLift_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void windLift_hitDetect(void) {
}

/* Update lift visibility, rotation and tracked riders. */
void windLift_update(GameObject* obj) {
    WindLiftPlacement* placement;
    WindLiftState* state = obj->extra;
    int alpha;
    GameObject* player;
    f32 pullStrength;
    int objectIndex;
    int slotIndex;
    int matchedSlot;
    int objectCount;
    u32* objects;
    int riderGameBit;
    placement = (WindLiftPlacement*)obj->anim.placement;
    if (state->enabled) {
        alpha = (int)(2.0f * timeDelta + (f32)(int)obj->anim.alpha);
        if (state->enableGameBit != -1 && mainGetBit(state->enableGameBit) == 0) {
            state->enabled = 0;
        }
    } else {
        alpha = (int)-(2.0f * timeDelta - (f32)(int)obj->anim.alpha);
        if (state->enableGameBit != -1 && mainGetBit(state->enableGameBit) != 0) {
            state->enabled = 1;
        }
    }
    obj->anim.alpha = (alpha < 0) ? 0 : ((alpha > WINDLIFT_ALPHA_MAX) ? WINDLIFT_ALPHA_MAX : alpha);
    if ((mainGetBit(GAMEBIT_CF_PowerOn) != 0 || state->duration > WINDLIFT_LONG_DURATION) && state->enabled) {
        int previousTimer = state->timer;
        state->timer = previousTimer + 1;
        if (previousTimer < WINDLIFT_SPIN_UP_FRAMES && mainGetBit(state->activationGameBit) == 0) {
            obj->anim.rotX -= ((framesThisStep * 100) * (state->timer * state->timer)) / WINDLIFT_SPIN_UP_FRAMES;
            Obj_SetActiveModelIndex(obj, 0);
            return;
        }
        Obj_SetActiveModelIndex(obj, 1);
        riderGameBit = mainGetBit(state->riderGameBit);
        {
            int rotationStep = framesThisStep * 0xb6;
            obj->anim.rotX -= rotationStep * ((riderGameBit << 2) + 0xe);
        }
        pullStrength = (f32)placement->pullStrength;
        player = Obj_GetPlayerObject();
        if (mainGetBit(state->activationGameBit) != 0) {
            if (!state->musicActive) {
                state->musicActive = 1;
                Music_Trigger(MUSICTRIG_DIM_Cavern, 1);
            }
            if (player != NULL) {
                windLift_updateRider(obj, player, &state->slots[0], pullStrength, riderGameBit, 1, state->duration,
                                     state->liftHeight);
            }
        } else {
            if (state->musicActive) {
                Music_Trigger(MUSICTRIG_DIM_Cavern, 0);
                state->musicActive = 0;
            }
            if ((state->slots[0].phaseFlags & WINDLIFT_SLOT_PHASE_FLAGS) != 0) {
                u8 flags;
                Player_SetLiftVelocityY(player, 0.0f);
                flags = state->slots[0].phaseFlags;
                if ((flags & WINDLIFT_SLOT_DIRECTION_FLAGS) != 0) {
                    state->slots[0].phaseFlags = flags | WINDLIFT_SLOT_FLAG_PENDING;
                }
                state->slots[0].riseSpeed = 0.0f;
                state->slots[0].oscillationCounter = 0;
                state->slots[0].phaseFlags &= ~WINDLIFT_SLOT_RESET_FLAGS;
            }
        }
        objects = (u32*)objGetAllOfType(WINDLIFT_RIDER_OBJECT_GROUP, &objectCount);
        objectCount = objectCount + 1;
        if (objectCount > WINDLIFT_SLOT_COUNT) {
            objectCount = WINDLIFT_SLOT_COUNT;
        }
        for (slotIndex = 1; slotIndex < WINDLIFT_SLOT_COUNT; slotIndex++) {
            state->slots[slotIndex].linkIndex = -1;
        }
        for (objectIndex = 1; objectIndex < objectCount; objectIndex++) {
            matchedSlot = -1;
            for (slotIndex = 1; slotIndex < WINDLIFT_SLOT_COUNT; slotIndex++) {
                if ((u32)state->slots[slotIndex].riderObject == *objects) {
                    matchedSlot = slotIndex;
                }
            }
            if (matchedSlot == -1) {
                for (slotIndex = 1; slotIndex < WINDLIFT_SLOT_COUNT; slotIndex++) {
                    if ((u32)state->slots[slotIndex].riderObject == 0) {
                        matchedSlot = slotIndex;
                        windLift_resetSlot(&state->slots[slotIndex]);
                        slotIndex = WINDLIFT_SLOT_SEARCH_END;
                    }
                }
                if (matchedSlot == -1) {
                    return;
                }
                state->slots[matchedSlot].riderObject = *objects;
            }
            state->slots[matchedSlot].linkIndex = matchedSlot;
            {
                GameObject* rider = (GameObject*)*objects;
                if ((rider->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0) {
                    objects++;
                } else if (rider != NULL) {
                    windLift_updateRider(obj, (GameObject*)*objects++, &state->slots[matchedSlot], pullStrength,
                                         riderGameBit, 0, state->duration, state->liftHeight);
                }
            }
        }
        for (slotIndex = 1; slotIndex < WINDLIFT_SLOT_COUNT; slotIndex++) {
            if (state->slots[slotIndex].linkIndex == -1) {
                state->slots[slotIndex].riderObject = 0;
            }
        }
    }
}

/* Initialise the lift's game bits, dimensions and rider slots. */
void windLift_init(GameObject* obj, WindLiftPlacement* placement) {
    int i;
    WindLiftState* state = obj->extra;
    state->activationGameBit = placement->activationGameBit;
    state->duration =
        seqPairTableLookup(gWindLiftDurationTable, WINDLIFT_DURATION_ENTRY_COUNT, state->activationGameBit);
    state->enableGameBit =
        seqPairTableLookup(gWindLiftEnableGameBitTable, WINDLIFT_ENABLE_GAME_BIT_ENTRY_COUNT, state->activationGameBit);
    if (state->enableGameBit == 0) {
        state->enableGameBit = -1;
    }
    if (state->duration == 0) {
        state->duration = WINDLIFT_DEFAULT_DURATION;
    }
    state->riderGameBit = placement->riderGameBit;
    state->timer = 0;
    if (placement->heightParam != 0) {
        state->liftHeight = WINDLIFT_HEIGHT_BYTE_SCALE * (f32)placement->heightParam;
    } else {
        state->liftHeight = WINDLIFT_DEFAULT_HEIGHT;
    }
    obj->anim.rootMotionScale =
        (obj->anim.modelInstance->rootMotionScaleBase * state->liftHeight) / WINDLIFT_DEFAULT_HEIGHT;
    if (mainGetBit(GAMEBIT_CF_PowerOn) != 0 || state->duration >= WINDLIFT_LONG_DURATION) {
        state->timer = WINDLIFT_SPIN_UP_FRAMES;
    }
    state->enabled = 1;
    if (state->enableGameBit != -1) {
        if (mainGetBit(state->enableGameBit) != 0) {
            state->timer = WINDLIFT_SPIN_UP_FRAMES;
        } else {
            state->enabled = 0;
            obj->anim.alpha = 0;
        }
    }
    {
        WindLiftState* slotState = state;
        for (i = 0; i < WINDLIFT_SLOT_COUNT; i++) {
            windLift_resetSlot(&slotState->slots[i]);
        }
    }
    objAddObjectType(obj, CFWINDLIFT_OBJECT_GROUP);
}

void windLift_release(void) {
}

void windLift_initialise(void) {
}

ObjectDescriptor gWindLiftObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)windLift_initialise,
    (ObjectDescriptorCallback)windLift_release,
    0,
    (ObjectDescriptorCallback)windLift_init,
    (ObjectDescriptorCallback)windLift_update,
    (ObjectDescriptorCallback)windLift_hitDetect,
    (ObjectDescriptorCallback)windLift_render,
    (ObjectDescriptorCallback)windLift_free,
    (ObjectDescriptorCallback)windLift_getObjectTypeId,
    windLift_getExtraSize,
};
