/*
 * ECSH_Cup (DLL 0x190) drives one cup in the Krazoa Test of Observation.
 *
 * The cup follows shuffle positions supplied by ECSH_Shrine, animates the
 * puzzle's rise and sink transitions, and reports player picks to the shrine.
 */
#include "dlls/objects/400_ECSH_Cup.h"

#include "dlls/objects/399_ECSH_Shrine.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/objhits.h"
#include "main/vecmath.h"

typedef struct ECSHShrineCallbackTable {
    void* unknown00[9];
    void (*getCupPosition)(u8 cupIndex, f32* outX, f32* outZ);
    void (*getPhaseAndSpiritCup)(int* outAnimState, u8* outSpiritCup);
    void (*setCupPosition)(u8 cupIndex, f32 x, f32 z);
    void (*checkCupPick)(u8 cupIndex);
} ECSHShrineCallbackTable;

STATIC_ASSERT(offsetof(ECSHShrineCallbackTable, getCupPosition) == 0x24);
STATIC_ASSERT(offsetof(ECSHShrineCallbackTable, getPhaseAndSpiritCup) == 0x28);
STATIC_ASSERT(offsetof(ECSHShrineCallbackTable, setCupPosition) == 0x2C);
STATIC_ASSERT(offsetof(ECSHShrineCallbackTable, checkCupPick) == 0x30);

typedef enum ECSHCupAnimState {
    ECSH_CUP_ANIM_STATE_STATIONARY = 0,
    ECSH_CUP_ANIM_STATE_MOVE_TO_SLOT = 1,
    ECSH_CUP_ANIM_STATE_STORE_SLOT_POSITION = 2,
    ECSH_CUP_ANIM_STATE_HOLD = 3,
    ECSH_CUP_ANIM_STATE_SNAP_TO_SLOT = 4,
    ECSH_CUP_ANIM_STATE_CHECK_PICK = 5,
    ECSH_CUP_ANIM_STATE_RISE = 6,
    ECSH_CUP_ANIM_STATE_SINK = 7,
    ECSH_CUP_ANIM_STATE_RUN_ACTIVE_SEQUENCE = 8,
} ECSHCupAnimState;

#define ECSH_CUP_PARTFX_IDLE              0x270
#define ECSH_CUP_PARTFX_TRANSITION        0x271
#define ECSH_CUP_ACTIVE_HIT_VOLUME_SLOT   10
#define ECSH_CUP_INACTIVE_HIT_VOLUME_SLOT 0
#define ECSH_CUP_OBJECT_TYPE_ID           0
#define ECSH_CUP_SEARCH_DISTANCE          500.0f
#define ECSH_CUP_PARTICLE_DELAY           10.0f
#define ECSH_CUP_BOB_DELAY                100.0f
#define ECSH_CUP_BOB_STEP                 0.02f
#define ECSH_CUP_MOVE_DURATION            100.0f
#define ECSH_CUP_TRANSITION_SPEED         0.5f
#define ECSH_CUP_TRANSITION_DISTANCE      50.0f
#define ECSH_CUP_ALPHA_STEP               2.0f
#define ECSH_CUP_FULL_ALPHA               0xFF
#define ECSH_CUP_FULL_ALPHA_FLOAT         255.0f
#define ECSH_CUP_PICK_DISTANCE            30.0f
#define ECSH_CUP_SEQUENCE_ACTIVE_SLOT     0
#define ECSH_CUP_SEQUENCE_PICKED_SLOT     1
#define ECSH_CUP_SEQUENCE_FLAGS           -1
#define ECSH_CUP_BOB_TIMER_RANDOM_MIN     0
#define ECSH_CUP_BOB_TIMER_RANDOM_MAX     0x258
#define ECSH_CUP_SPIN_RATE_RANDOM_MIN     -0x320
#define ECSH_CUP_SPIN_RATE_RANDOM_MAX     0x320
#define ECSH_CUP_INITIAL_BOB_DIRECTION    1

GameObject* gECSHCupShrineObject;
const Vec3f gECSHCupZeroVector = {0.0f, 0.0f, 0.0f};

int ecshCup_getExtraSize(void) {
    return sizeof(ECSHCupState);
}

int ecshCup_getObjectTypeId(void) {
    return ECSH_CUP_OBJECT_TYPE_ID;
}

void ecshCup_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void ecshCup_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void ecshCup_hitDetect(void) {
}

void ecshCup_update(GameObject* obj) {
    f32 searchDistance;
    int mode;
    int modeCopy;
    u8 spiritCup;
    Vec3f slotPosition;
    GameObject* player = Obj_GetPlayerObject();
    ECSHCupState* state = obj->extra;
    f32 fade;

    slotPosition = gECSHCupZeroVector;
    searchDistance = ECSH_CUP_SEARCH_DISTANCE;
    mode = -1;
    spiritCup = 0;
    if (gECSHCupShrineObject == NULL) {
        gECSHCupShrineObject = objGetNearestTypeTo(ECSH_SHRINE_OBJECT_GROUP, obj, &searchDistance);
    }
    if (gECSHCupShrineObject != NULL && gECSHCupShrineObject->anim.classId != 0) {
        (*(ECSHShrineCallbackTable**)gECSHCupShrineObject->anim.dll)->getPhaseAndSpiritCup(&mode, &spiritCup);
        obj->anim.rotX += state->spinRate;
        if (mode != ECSH_CUP_ANIM_STATE_RISE) {
            state->particleTimer -= timeDelta;
            if (state->particleTimer <= 0.0f) {
                state->particleTimer = ECSH_CUP_PARTICLE_DELAY;
                if (mode != ECSH_CUP_ANIM_STATE_HOLD && mode != ECSH_CUP_ANIM_STATE_RISE &&
                    mode != ECSH_CUP_ANIM_STATE_SINK) {
                    (*gPartfxInterface)->spawnObject(obj, ECSH_CUP_PARTFX_IDLE, NULL, 0, -1, NULL);
                }
            }
        }
        state->bobTimer -= timeDelta;
        if (state->bobTimer <= 0.0f) {
            state->bobDirection = (u32)state->bobDirection * -1;
            state->bobTimer = ECSH_CUP_BOB_DELAY;
        }
        obj->anim.localPosY += ECSH_CUP_BOB_STEP * state->bobDirection;
        if (mode == ECSH_CUP_ANIM_STATE_MOVE_TO_SLOT && state->currentAnimState == ECSH_CUP_ANIM_STATE_MOVE_TO_SLOT) {
            obj->anim.localPosX += state->velocityX * timeDelta;
            obj->anim.localPosZ += state->velocityZ * timeDelta;
            ObjHits_EnableObject(obj);
            ObjHits_SetHitVolumeSlot(&obj->anim, ECSH_CUP_ACTIVE_HIT_VOLUME_SLOT, 1, 0);
            ObjHits_SyncObjectPositionIfDirty(obj);
        } else {
            ObjHits_EnableObject(obj);
            ObjHits_SetHitVolumeSlot(&obj->anim, ECSH_CUP_INACTIVE_HIT_VOLUME_SLOT, 0, 0);
            ObjHits_SyncObjectPositionIfDirty(obj);
        }
        modeCopy = mode;
        if (modeCopy == ECSH_CUP_ANIM_STATE_RISE) {
            if (obj->anim.localPosY < state->transitionHeight) {
                obj->anim.localPosY += ECSH_CUP_TRANSITION_SPEED * timeDelta;
            }
            if (obj->anim.renderAlpha != ECSH_CUP_FULL_ALPHA) {
                fade = (f32)(u32)obj->anim.renderAlpha;
                fade += ECSH_CUP_ALPHA_STEP * timeDelta;
                if (fade >= ECSH_CUP_FULL_ALPHA_FLOAT) {
                    fade = ECSH_CUP_FULL_ALPHA_FLOAT;
                }
                obj->anim.renderAlpha = (u8)fade;
            }
            state->particleTimer -= timeDelta;
            if (state->particleTimer <= 0.0f) {
                state->particleTimer = ECSH_CUP_PARTICLE_DELAY;
                (*gPartfxInterface)->spawnObject(obj, ECSH_CUP_PARTFX_TRANSITION, NULL, 0, -1, NULL);
            }
        } else if (modeCopy == ECSH_CUP_ANIM_STATE_SINK) {
            if (obj->anim.localPosY > state->transitionHeight - ECSH_CUP_TRANSITION_DISTANCE) {
                obj->anim.localPosY -= ECSH_CUP_TRANSITION_SPEED * timeDelta;
                state->particleTimer -= timeDelta;
                if (state->particleTimer <= 0.0f) {
                    state->particleTimer = ECSH_CUP_PARTICLE_DELAY;
                    if (mode != ECSH_CUP_ANIM_STATE_HOLD) {
                        (*gPartfxInterface)->spawnObject(obj, ECSH_CUP_PARTFX_TRANSITION, NULL, 0, -1, NULL);
                    }
                }
            }
            if (obj->anim.renderAlpha != 0) {
                fade = (f32)(u32)obj->anim.renderAlpha;
                fade -= ECSH_CUP_ALPHA_STEP * timeDelta;
                if (fade <= 0.0f) {
                    fade = 0.0f;
                }
                obj->anim.renderAlpha = (u8)fade;
            }
        } else if (modeCopy == ECSH_CUP_ANIM_STATE_RUN_ACTIVE_SEQUENCE && modeCopy != state->currentAnimState) {
            if (state->cupIndex == spiritCup) {
                (*gObjectTriggerInterface)->runSequence(ECSH_CUP_SEQUENCE_ACTIVE_SLOT, obj, ECSH_CUP_SEQUENCE_FLAGS);
            }
            state->currentAnimState = mode;
        } else if (modeCopy == ECSH_CUP_ANIM_STATE_MOVE_TO_SLOT && modeCopy != state->currentAnimState) {
            (*(ECSHShrineCallbackTable**)gECSHCupShrineObject->anim.dll)
                ->getCupPosition((u8)state->cupIndex, &slotPosition.x, &slotPosition.z);
            state->velocityX = (slotPosition.x - obj->anim.localPosX) / ECSH_CUP_MOVE_DURATION;
            state->velocityZ = (slotPosition.z - obj->anim.localPosZ) / ECSH_CUP_MOVE_DURATION;
            state->startPosX = obj->anim.localPosX;
            state->startPosZ = obj->anim.localPosZ;
            state->currentAnimState = mode;
        } else if (modeCopy == ECSH_CUP_ANIM_STATE_STATIONARY && modeCopy != state->currentAnimState) {
            state->velocityX = 0.0f;
            state->velocityZ = 0.0f;
            state->currentAnimState = mode;
        } else if (modeCopy == ECSH_CUP_ANIM_STATE_STORE_SLOT_POSITION && modeCopy != state->currentAnimState) {
            state->velocityX = 0.0f;
            state->velocityZ = 0.0f;
            (*(ECSHShrineCallbackTable**)gECSHCupShrineObject->anim.dll)
                ->setCupPosition((u8)state->cupIndex, obj->anim.localPosX, obj->anim.localPosZ);
            state->currentAnimState = mode;
        } else if (modeCopy == ECSH_CUP_ANIM_STATE_HOLD && modeCopy != state->currentAnimState) {
            state->currentAnimState = mode;
        } else if (modeCopy == ECSH_CUP_ANIM_STATE_SNAP_TO_SLOT && modeCopy != state->currentAnimState) {
            (*(ECSHShrineCallbackTable**)gECSHCupShrineObject->anim.dll)
                ->getCupPosition((u8)state->cupIndex, &slotPosition.x, &slotPosition.z);
            obj->anim.localPosX = slotPosition.x;
            obj->anim.localPosZ = slotPosition.z;
            state->currentAnimState = mode;
        } else if (modeCopy == ECSH_CUP_ANIM_STATE_CHECK_PICK) {
            if (player != NULL) {
                if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < ECSH_CUP_PICK_DISTANCE) {
                    (*(ECSHShrineCallbackTable**)gECSHCupShrineObject->anim.dll)->checkCupPick((u8)state->cupIndex);
                    if (state->cupIndex == spiritCup) {
                        (*gObjectTriggerInterface)
                            ->runSequence(ECSH_CUP_SEQUENCE_PICKED_SLOT, obj, ECSH_CUP_SEQUENCE_FLAGS);
                    }
                }
            }
        }
    }
}

void ecshCup_init(GameObject* obj, const ECSHCupPlacement* placement) {
    ECSHCupState* state;
    f32 searchDistance;

    state = obj->extra;
    searchDistance = ECSH_CUP_SEARCH_DISTANCE;
    gECSHCupShrineObject = NULL;
    state->startPosX = obj->anim.localPosX;
    state->startPosY = obj->anim.localPosY;
    state->startPosZ = obj->anim.localPosZ;
    state->transitionHeight = obj->anim.localPosY;
    obj->anim.localPosY -= ECSH_CUP_TRANSITION_DISTANCE;
    {
        f32 zero = 0.0f;
        state->velocityX = zero;
        state->velocityY = zero;
        state->velocityZ = zero;
    }
    state->currentAnimState = ECSH_CUP_ANIM_STATE_STATIONARY;
    state->cupIndex = placement->cupIndex;
    state->bobTimer = randomGetRange(ECSH_CUP_BOB_TIMER_RANDOM_MIN, ECSH_CUP_BOB_TIMER_RANDOM_MAX);
    state->spinRate = randomGetRange(ECSH_CUP_SPIN_RATE_RANDOM_MIN, ECSH_CUP_SPIN_RATE_RANDOM_MAX);
    state->bobDirection = ECSH_CUP_INITIAL_BOB_DIRECTION;
    obj->anim.renderAlpha = 0;
    state->particleTimer = 0.0f;
    if (gECSHCupShrineObject == NULL) {
        gECSHCupShrineObject = objGetNearestTypeTo(ECSH_SHRINE_OBJECT_GROUP, obj, &searchDistance);
    }
    ObjHits_EnableObject(obj);
    ObjHits_SetHitVolumeSlot(&obj->anim, ECSH_CUP_INACTIVE_HIT_VOLUME_SLOT, 0, 0);
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void ecshCup_release(void) {
}

void ecshCup_initialise(void) {
}

ObjectDescriptor gECSHCupObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ecshCup_initialise,
    (ObjectDescriptorCallback)ecshCup_release,
    0,
    (ObjectDescriptorCallback)ecshCup_init,
    (ObjectDescriptorCallback)ecshCup_update,
    (ObjectDescriptorCallback)ecshCup_hitDetect,
    (ObjectDescriptorCallback)ecshCup_render,
    (ObjectDescriptorCallback)ecshCup_free,
    (ObjectDescriptorCallback)ecshCup_getObjectTypeId,
    ecshCup_getExtraSize,
};
