#include "dlls/objects/280_Duster.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objHitReact_types.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/dll/player_api.h"
#include "main/obj_message.h"
#include "main/objhits.h"

#define DUSTER_MOVE_STEP_SCALE             0.02f
#define DUSTER_MESSAGE_IN_RANGE            0x7000A
#define DUSTER_MESSAGE_DEPOSIT             0x7000B
#define DUSTER_PARTICLE_DEPOSIT            0x51A
#define DUSTER_PARTICLE_BOUNCE             0x51F
#define DUSTER_GAME_BIT_COMPLETE_THRESHOLD 0x6FE
#define DUSTER_COMPLETE_GAME_BIT_OFFSET    0x64
#define DUSTER_DRIFT_DIRECTION_SPIN        4
#define DUSTER_DRIFT_DIRECTION_MAX         4
#define DUSTER_HELD_OBJECT_NONE            -1
#define DUSTER_HIT_REACTION_PRIORITY       0xE
#define DUSTER_HIT_REACTION_TIMER          0xFA
#define DUSTER_SETTLE_TIMER_MAX            0x32
#define DUSTER_MESSAGE_QUEUE_SIZE          1

typedef struct DusterCharacterState {
    u8 pad00[9];
    u8 collectedCount;
    u8 maxCollectedCount;
} DusterCharacterState;

STATIC_ASSERT(offsetof(DusterCharacterState, collectedCount) == 0x9);
STATIC_ASSERT(offsetof(DusterCharacterState, maxCollectedCount) == 0xA);

int duster_SeqFn(GameObject* obj) {
    DusterObjectState* state = obj->extra;
    state->flags.floorCached = 0;
    return 0;
}

int duster_getExtraSize(void) {
    return DUSTER_OBJECT_STATE_SIZE;
}

void duster_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    DusterObjectState* state = obj->extra;
    if (visible == 0 || state->active == 0 || state->complete != 0) {
        return;
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void duster_hitDetect(GameObject* obj) {
    DusterObjectState* state;
    TrackLineIntersectResult hit;
    int hitResult;
    state = obj->extra;
    hitResult = trackGetLineIntersect(&obj->anim.previousLocalPosX, &obj->anim.localPosX, 6.0f, 2,
                                   &hit, obj, 8, -1, 255, 0);
    if (hitResult != 0) {
        state->priorityHit = 1;
    }
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
}

void duster_update(GameObject* obj) {
    DusterObjectState* state;
    DusterPlacement* placement;
    GameObject* player;
    TrackGroundHit** floorHits;
    int message;
    int nextCollectedCount;
    int floorHitCount;
    int floorIndex;
    int bestFloorIndex;
    f32 bestFloorDelta;
    f32 verticalDelta;
    MatrixTransform launch;
    DusterCharacterState* characterState;

    state = obj->extra;
    placement = (DusterPlacement*)obj->anim.placementData;
    player = Obj_GetPlayerObject();

    while (ObjMsg_Pop(obj, (u32*)&message, 0, 0) != 0) {
        switch (message) {
        case DUSTER_MESSAGE_DEPOSIT:
            ((void (*)(void*, u16))Sfx_PlayFromObject)(obj, SFXTRIG_sc_cam90_c);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTICLE_DEPOSIT, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTICLE_DEPOSIT, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTICLE_DEPOSIT, NULL, 1, -1, NULL);
            mainSetBits(state->completeGameBit, 1);
            characterState = (DusterCharacterState*)(*gMapEventInterface)->getCurCharacterState();
            characterState->collectedCount =
                (characterState->maxCollectedCount < (nextCollectedCount = characterState->collectedCount + 1))
                    ? characterState->maxCollectedCount
                    : nextCollectedCount;
            state->complete = 1;
            break;
        }
    }

    if (state->active == 0 || state->complete == 1) {
        if (state->active == 0) {
            state->active = mainGetBit(state->activeGameBit);
            state->settleTimer = 0;
        }
        return;
    }

    if (obj->anim.velocityY > -6.0f) {
        obj->anim.velocityY = -0.05f * timeDelta + obj->anim.velocityY;
    }

    state->priorityHit = 0;
    if (state->flags.floorCached == 0) {
        floorHitCount =
            trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &floorHits, 0, 0);
        bestFloorDelta = 100000.0f;
        bestFloorIndex = -1;
        for (floorIndex = 0; floorIndex < floorHitCount; floorIndex++) {
            verticalDelta = floorHits[floorIndex]->height - obj->anim.localPosY;
            if (verticalDelta < 0.0f) {
                verticalDelta = -verticalDelta;
            }
            if (verticalDelta < bestFloorDelta) {
                bestFloorIndex = floorIndex;
                bestFloorDelta = verticalDelta;
            }
        }
        if (bestFloorIndex != -1) {
            state->flags.floorCached = 1;
            state->floorY = floorHits[bestFloorIndex]->height;
            obj->anim.velocityY = 0.0f;
        }
        if (state->flags.floorCached == 0) {
            state->floorY = placement->base.posY;
            state->flags.floorCached = 1;
        }
    }

    if (obj->anim.localPosY < state->floorY) {
        obj->anim.localPosY = state->floorY;
        obj->anim.velocityY = 0.0f;
    }

    if (state->settleTimer == 0 && state->hitReactTimer == 0) {
        if (ObjAnim_AdvanceCurrentMove(obj, state->moveStepScale, timeDelta, NULL) != 0 ||
            state->priorityHit != 0) {
            ((void (*)(void*, u16))Sfx_PlayFromObject)(obj, SFXTRIG_en_lflsh3_c);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTICLE_BOUNCE, NULL, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTICLE_BOUNCE, NULL, 2, -1, NULL);
            state->driftDirection = randomGetRange(0, DUSTER_DRIFT_DIRECTION_MAX);
            if (state->useLaunchVelocity != 0) {
                obj->anim.velocityX = 0.2f;
                launch.z = launch.y = launch.x = obj->anim.velocityZ = 0.0f;
                launch.scale = 1.0f;
                launch.rotZ = 0;
                launch.rotY = 0;
                launch.rotX = obj->anim.rotX;
                vecRotateZXY(&launch.rotX, &obj->anim.velocityX);
            } else {
                obj->anim.velocityZ = obj->anim.velocityX = 0.0f;
            }
            if (state->hitReactionActive != 0) {
                state->hitReactTimer = DUSTER_HIT_REACTION_TIMER;
            }
        } else {
            obj->anim.localPosX += obj->anim.velocityX * timeDelta;
            obj->anim.localPosZ += obj->anim.velocityZ * timeDelta;
        }

        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == DUSTER_HIT_REACTION_PRIORITY) {
            state->hitReactionActive = 1;
            ((void (*)(void*, u16))Sfx_PlayFromObject)(obj, SFXTRIG_dn_boar1_c_4d);
        }
    } else {
        if (state->settleTimer != 0) {
            state->settleTimer -= (s16)timeDelta;
            if (state->settleTimer <= 0) {
                state->settleTimer = 0;
            }
        }
        if (state->hitReactTimer != 0) {
            state->hitReactTimer -= (s16)timeDelta;
            if (state->hitReactTimer <= 0) {
                state->hitReactTimer = 0;
                state->hitReactionActive = 0;
            }
        }
    }

    if (state->driftDirection == DUSTER_DRIFT_DIRECTION_SPIN) {
        if (state->priorityHit != 0) {
            obj->anim.rotX = (s16)(obj->anim.rotX - 0x7fff);
            state->driftDirection = 0;
        }
        obj->anim.rotX = (s16)((f32)obj->anim.rotX + 3000.0f * timeDelta);
    }

    verticalDelta = player->anim.localPosY - obj->anim.localPosY;
    if (verticalDelta < 0.0f) {
        verticalDelta = -verticalDelta;
    }
    if (verticalDelta < 30.0f &&
        Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX) < 20.0f &&
        Obj_IsParentSlackClear(player) != 0) {
        if (mainGetBit(GAMEBIT_SawBafomdad) == 0) {
            state->heldObjectId = DUSTER_HELD_OBJECT_NONE;
            ObjHits_DisableObject(obj);
            ObjMsg_SendToObject(player, DUSTER_MESSAGE_IN_RANGE, obj, (u32)&state->heldObjectId);
            mainSetBits(GAMEBIT_SawBafomdad, 1);
        } else {
            characterState = (DusterCharacterState*)(*gMapEventInterface)->getCurCharacterState();
            if (characterState->collectedCount < characterState->maxCollectedCount) {
                Sfx_PlayFromObject(obj, SFXTRIG_sc_cam90_c);
                (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTICLE_DEPOSIT, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTICLE_DEPOSIT, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTICLE_DEPOSIT, NULL, 1, -1, NULL);
                mainSetBits(state->completeGameBit, 1);
                characterState = (DusterCharacterState*)(*gMapEventInterface)->getCurCharacterState();
                characterState->collectedCount =
                    (characterState->maxCollectedCount < (nextCollectedCount = characterState->collectedCount + 1))
                        ? characterState->maxCollectedCount
                        : nextCollectedCount;
                state->complete = 1;
                obj->anim.alpha = 1;
            }
        }
        if (obj->anim.hitReactState != NULL) {
            ObjHits_DisableObject(obj);
        }
    }

    obj->anim.localPosY += obj->anim.velocityY;
}

void duster_init(GameObject* obj, DusterPlacement* placement) {
    DusterObjectState* state;
    ObjHitReactState* hitReactState;

    state = obj->extra;
    state->settleTimer = randomGetRange(0, DUSTER_SETTLE_TIMER_MAX);
    state->moveStepScale = DUSTER_MOVE_STEP_SCALE;
    state->activeGameBit = placement->activeGameBit;
    if (state->activeGameBit >= DUSTER_GAME_BIT_COMPLETE_THRESHOLD) {
        state->active = 1;
        state->completeGameBit = state->activeGameBit;
    } else {
        state->active = mainGetBit(state->activeGameBit);
        state->completeGameBit = state->activeGameBit + DUSTER_COMPLETE_GAME_BIT_OFFSET;
    }
    state->complete = mainGetBit(state->completeGameBit);
    hitReactState = obj->anim.hitReactState;
    if (hitReactState != NULL && state->active == 0) {
        hitReactState->flags = (s16)(hitReactState->flags | 1);
    }
    if ((state->complete != 0 || state->active == 0) && obj->anim.hitReactState != NULL) {
        ObjHits_DisableObject(obj);
    }
    ObjMsg_AllocQueue(obj, DUSTER_MESSAGE_QUEUE_SIZE);
    obj->animEventCallback = duster_SeqFn;
}

ObjectDescriptor gDusterObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)duster_init,
    (ObjectDescriptorCallback)duster_update,
    (ObjectDescriptorCallback)duster_hitDetect,
    (ObjectDescriptorCallback)duster_render,
    0,
    0,
    duster_getExtraSize,
};
