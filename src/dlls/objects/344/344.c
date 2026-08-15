/* Carryable gunpowder- and metal-barrel behavior. */

#include "dlls/objects/344.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "dolphin/mtx/vec.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/carryable_interface.h"
#include "main/dll/dll_0243_dbholecontrol1.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/dll_02B5_timer.h"
#include "main/dll/player_api.h"
#include "main/dll/player_motion.h"
#include "main/dll/player_state.h"
#include "main/dll/tricky_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/lightmap_api.h"
#include "main/maketex_timer_api.h"
#include "main/objtype.h"
#include "main/obj_link.h"
#include "main/obj_message.h"
#include "main/obj_query.h"
#include "main/object_render.h"
#include "main/object_update_list.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "string.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_80136a40.h"
#include "main/dll/savegame_object_api.h"

#define GUNPOWDER_BARREL_HIT_VOLUME_SLOT_BLAST     5
#define GUNPOWDER_BARREL_HIT_VOLUME_SLOT_BODY      0xE
#define GUNPOWDER_BARREL_SEQUENCE_CANNON_RANGE     0x754
#define GUNPOWDER_BARREL_MESSAGE_PLAYER_HELD       0xF
#define GUNPOWDER_BARREL_MESSAGE_PLAYER_RELEASED   0x10
#define GUNPOWDER_BARREL_MESSAGE_QUEUE_CAPACITY    8
#define GUNPOWDER_BARREL_CARRYABLE_MODE            5
#define GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING      0x01
#define GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT     0x02
#define GUNPOWDER_BARREL_DETONATION_TRIGGER_IMPACT 4
#define GUNPOWDER_BARREL_DETONATION_TRIGGER_TIMER  0xA
#define GUNPOWDER_BARREL_FUSE_DURATION_FRAMES      0x14
#define GUNPOWDER_BARREL_RESPAWN_DURATION_FRAMES   0x3C
#define GUNPOWDER_BARREL_RELEASE_DURATION_FRAMES   0x5A
#define GUNPOWDER_BARREL_GENERATOR_RELEASE_FRAME   0x46
#define GUNPOWDER_BARREL_MAX_ALPHA                 0xFF

typedef struct GunpowderBarrelTimerInterface {
    void* pad00[4];
    void (*render)(GameObject* timer, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
} GunpowderBarrelTimerInterface;

STATIC_ASSERT(offsetof(GunpowderBarrelTimerInterface, render) == 0x10);

typedef union GunpowderBarrelCollisionScratch {
    TrackBBoxHit hit;
    f32 words[24];
} GunpowderBarrelCollisionScratch;

STATIC_ASSERT(sizeof(GunpowderBarrelCollisionScratch) == 0x60);

f32 gGunpowderBarrelReleaseOffset = 10.0f;
f32 gGunpowderBarrelImpactSoundSpeedThreshold = 0.4f;
f32 gGunpowderBarrelFallDetonationThreshold = 170.0f;
int gunpowderBarrel_isHeld(GameObject* obj) {
    return ((GunpowderBarrelState*)obj->extra)->heldFlags.held;
}

int gunpowderBarrel_canBeGrabbed(GameObject* obj) {
    GunpowderBarrelState* state = obj->extra;
    int result = 0;
    if (state->heldByCarryInterface == 0 && !state->respawnTimer && (*gCarryableInterface)->getCarryState(state) == 0) {
        result = 1;
    }
    return result;
}

void gunpowderBarrel_clearHeldState(GameObject* obj) {
    GunpowderBarrelState* state = obj->extra;
    f32 zero = 0.0f;
    state->throwVelocityY = zero;
    state->throwVelocityX = zero;
    state->throwVelocityZ = zero;
    state->motionFlags = state->motionFlags | GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING;
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
    state->accumulatedFallVelocity = zero;
    state->heldFlags.held = 0;
}

void gunpowderBarrel_setHeldState(GameObject* obj) {
    GunpowderBarrelState* state = obj->extra;
    state->heldFlags.held = 1;
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
    state->motionFlags = state->motionFlags & ~GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT;
}

void gunpowderBarrel_launchAtTarget(GameObject* obj, u8 usePlayerStrength) {
    int index;
    u32* generators;
    GameObject* generator;
    GunpowderBarrelPlacement* placement;
    u32* generatorIter;
    int generatorCount;
    GunpowderBarrelState* state = obj->extra;
    PlayerState* playerState;
    MatrixTransform transform;
    f32 zero;
    f32 originalX, originalY, originalZ;

    playerState = ((GameObject*)Obj_GetPlayerObject())->extra;
    state->throwVelocityX = 0.0f;
    if (usePlayerStrength != 0) {
        state->throwVelocityY = 0.75f * playerState->baddie.inputMagnitude + 2.2f;
        state->throwVelocityZ = -0.75f * playerState->baddie.inputMagnitude + -2.2f;
    } else {
        state->throwVelocityY = 1.5f;
        state->throwVelocityZ = -1.5f;
    }
    zero = 0.0f;
    transform.x = zero;
    transform.y = zero;
    transform.z = zero;
    transform.scale = 1.0f;
    transform.rotZ = 0;
    transform.rotY = 0;
    transform.rotX = state->launchYaw;
    vecRotateZXY(&transform.rotX, &state->throwVelocityX);
    state->motionFlags = state->motionFlags | GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING;
    Sfx_PlayFromObject(obj, SFXTRIG_barrel_throw_d3);
    state->motionFlags = state->motionFlags | GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT;
    if (state->configFlags.returnHome != 0) {
        placement = (GunpowderBarrelPlacement*)obj->anim.placement;
        generator = NULL;
        if (placement->generatorLinkId != 0) {
            generators = (u32*)objGetAllOfType(BARREL_GENERATOR_OBJECT_GROUP, &generatorCount);
            index = 0;
            generatorIter = generators;
            for (; index < generatorCount; index++) {
                if (placement->generatorLinkId == barrelgener_getLinkId((GameObject*)(*generatorIter))) {
                    generator = (GameObject*)generators[index];
                    break;
                }
                generatorIter++;
            }
        } else {
            generator = objGetNearestTypeTo(BARREL_GENERATOR_OBJECT_GROUP, obj, 0);
        }
        if (generator != NULL) {
            originalX = obj->anim.localPosX;
            originalY = obj->anim.localPosY;
            originalZ = obj->anim.localPosZ;
            obj->anim.localPosX = generator->anim.localPosX;
            obj->anim.localPosY = generator->anim.localPosY;
            obj->anim.localPosZ = generator->anim.localPosZ;
            saveGame_saveObjectPos(obj);
            obj->anim.localPosX = originalX;
            obj->anim.localPosY = originalY;
            obj->anim.localPosZ = originalZ;
        }
    }
}

void gunpowderBarrel_setPlayerHeldState(GameObject* obj, u8 heldByPlayer) {
    GunpowderBarrelState* state;
    GameObject* objectAddress = obj;
    ObjHitsPriorityState* hitState;
    state = objectAddress->extra;
    hitState = (ObjHitsPriorityState*)objectAddress->anim.hitReactState;
    if (heldByPlayer != 0) {
        hitState->lateralResponseWeight = 1;
        hitState->axialResponseWeight = 1;
        objectAddress->anim.resetHitboxFlags =
            (u8)(objectAddress->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        state->heldFlags.playerHeld = 1;
        state->motionFlags = state->motionFlags & ~GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT;
        ObjHits_SetFlags((ObjAnimComponent*)objectAddress, OBJHITS_PRIORITY_STATE_IMMOVABLE | 0x80);
        ObjHits_ClearSourceMask((ObjAnimComponent*)objectAddress, 1);
        ObjHits_EnableObject(objectAddress);
        ObjHits_SyncObjectPositionIfDirty(objectAddress);
    } else {
        hitState->lateralResponseWeight = objectAddress->anim.modelInstance->lateralResponseWeight;
        hitState->axialResponseWeight = objectAddress->anim.modelInstance->axialResponseWeight;
        state->heldFlags.playerHeld = 0;
        objectAddress->anim.resetHitboxFlags =
            (u8)(objectAddress->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
        ObjHits_ClearFlags((ObjAnimComponent*)objectAddress, OBJHITS_PRIORITY_STATE_IMMOVABLE);
        state->motionFlags = state->motionFlags | GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING;
    }
}

void gunpowderBarrel_addThrowVelocity(GameObject* obj, f32* velocity) {
    GunpowderBarrelState* state = obj->extra;
    if (state->heldByCarryInterface != 0) {
        return;
    }
    if (state->fuseFrames != 0) {
        return;
    }
    state->throwVelocityY = state->throwVelocityY + velocity[1];
    state->throwVelocityX = state->throwVelocityX + velocity[0];
    state->throwVelocityZ = state->throwVelocityZ + velocity[2];
    state->motionFlags = state->motionFlags | GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING;
}

void gunpowderBarrel_homeOnTarget(GameObject* obj, s16 rotYModeArg, s16 rotZModeArg) {
    f32 targetDeltaX;
    f32 targetDeltaY;
    f32 targetDeltaZ;
    f32 zero;
    f32 approachRate;
    f32 playerHeightDelta;
    int rotYMode;
    int rotZMode;
    GameObject* player;
    GameObject* target;
    f32 searchRadius = 300.0f;
    player = Obj_GetPlayerObject();
    target = objGetNearestTypeTo(DBHOLE_CONTROL1_OBJECT_GROUP, obj, &searchRadius);
    if (target == NULL) {
        return;
    }
    playerHeightDelta = target->anim.localPosY - player->anim.localPosY;
    playerHeightDelta = (playerHeightDelta >= 0.0f) ? playerHeightDelta : -playerHeightDelta;
    if (playerHeightDelta < 30.0f) {
        return;
    }
    targetDeltaX = target->anim.localPosX - obj->anim.localPosX;
    targetDeltaY = target->anim.localPosY - obj->anim.localPosY;
    zero = 0.0f;
    if (targetDeltaY > zero) {
        return;
    }
    targetDeltaZ = target->anim.localPosZ - obj->anim.localPosZ;
    if (targetDeltaY != zero) {
        approachRate = obj->anim.velocityY / targetDeltaY;
    } else {
        approachRate = zero;
    }
    if (approachRate >= 1.0f) {
        Sfx_PlayFromObject(obj, SFXTRIG_barrel_putdown);
        approachRate = 1.0f;
        obj->anim.velocityY = targetDeltaY;
        target->anim.localPosX += 20.0f;
        target->anim.velocityZ += 20.0f;
        if (target->anim.velocityZ > 180.0f) {
            target->anim.localPosX -= target->anim.velocityZ;
            target->anim.velocityZ = 0.0f;
        }
        obj->anim.rotY = 0;
        obj->anim.rotZ = 0;
        rotYModeArg = 0;
        rotZModeArg = 0;
    }
    obj->anim.velocityX = targetDeltaX * approachRate;
    obj->anim.velocityZ = targetDeltaZ * approachRate;
    rotYMode = rotYModeArg;
    if (rotYMode != 0) {
        f32 t;
        f32 factor;
        if (rotYMode == 1) {
            factor = 65536.0f - (f32)(u16)obj->anim.rotY;
            t = factor * approachRate;
        } else {
            t = (f32)(u16)obj->anim.rotY;
            factor = approachRate * rotYMode;
            t *= factor;
        }
        obj->anim.rotY = (f32)obj->anim.rotY + t;
    }
    rotZMode = rotZModeArg;
    if (rotZMode != 0) {
        f32 t;
        if (rotZMode == 1) {
            t = 0.0f;
        } else {
            t = (f32)(u16)obj->anim.rotZ;
            t = t * (approachRate * rotZMode);
        }
        obj->anim.rotZ = (f32)obj->anim.rotZ + t;
    }
}

void gunpowderBarrel_triggerExplosion(GameObject* obj) {
    GunpowderBarrelState* state;
    GameObject* hitObject;
    int generatorCount;
    u8* tricky;
    int* timerObject;

    state = obj->extra;
    if (ObjHits_GetPriorityHit(obj, &hitObject, 0, 0) != 0 ||
        (((ObjHitsPriorityState*)obj->anim.hitReactState)->contactFlags != 0 &&
         (state->motionFlags & GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT) != 0)) {
        state->detonationTrigger += 1;
        state->motionFlags = state->motionFlags | GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING;
    }
    if (state->detonationTrigger != 0) {
        if (state->configFlags.returnHome) {
            int index;
            u32* generators;
            GameObject* generator;
            GunpowderBarrelPlacement* placement;
            u32* generatorIter;
            placement = (GunpowderBarrelPlacement*)obj->anim.placement;
            generator = NULL;
            if (placement->generatorLinkId != 0) {
                generators = (u32*)objGetAllOfType(BARREL_GENERATOR_OBJECT_GROUP, &generatorCount);
                index = 0;
                generatorIter = generators;
                for (; index < generatorCount; index++) {
                    if (placement->generatorLinkId == barrelgener_getLinkId((GameObject*)(*generatorIter))) {
                        generator = (GameObject*)generators[index];
                        break;
                    }
                    generatorIter++;
                }
            } else {
                generator = objGetNearestTypeTo(BARREL_GENERATOR_OBJECT_GROUP, obj, 0);
            }
            if (generator != NULL) {
                f32 originalX, originalY, originalZ;
                originalX = obj->anim.localPosX;
                originalY = obj->anim.localPosY;
                originalZ = obj->anim.localPosZ;
                obj->anim.localPosX = generator->anim.localPosX;
                obj->anim.localPosY = generator->anim.localPosY;
                obj->anim.localPosZ = generator->anim.localPosZ;
                saveGame_saveObjectPos(obj);
                obj->anim.localPosX = originalX;
                obj->anim.localPosY = originalY;
                obj->anim.localPosZ = originalZ;
            }
        }
        ObjHits_ClearFlags((ObjAnimComponent*)obj, 0x80);
        ObjHits_SetSourceMask((ObjAnimComponent*)obj, 1);
        ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, 0x14, -5, 0x14);
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, GUNPOWDER_BARREL_HIT_VOLUME_SLOT_BLAST, 4, 0);
        Sfx_PlayFromObject(obj, SFXTRIG_en_barrelblow11_d1);
        obj->anim.localPosY += 10.0f;
        spawnExplosion(obj, 0.0f, 1, 1, 0, 0, 0, 1, 0);
        if (state->heldByCarryInterface != 0) {
            (*gCarryableInterface)->stopCarrying(obj, state);
            state->heldByCarryInterface = 0;
        }
        state->fuseFrames = 1;
        state->heldFlags.held = 0;
        objFreeObjectType(obj, GUNPOWDER_BARREL_OBJECT_GROUP);
        if (obj->anim.parent != 0) {
            state->radiusGrowthPerFrame = 2.2f;
        } else {
            state->radiusGrowthPerFrame = 2.2f;
        }
        tricky = (u8*)getTrickyObject();
        if (tricky != 0) {
            trickyImpress((GameObject*)tricky);
        }
        state->motionFlags = state->motionFlags & ~GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT;
        timerObject = (int*)state->linkedTimerObject;
        if (timerObject != 0) {
            timer_clearManualFlags((GameObject*)(timerObject));
        }
    }
}

void gunpowderBarrel_updatePhysics(GameObject* obj) {
    GunpowderBarrelState* state;
    GameObject* contactObject;
    f32 surfaceY;
    int blockIndex;
    f32 deltaTime;

    state = obj->extra;
    if (state->heldFlags.held) {
        return;
    }
    blockIndex = objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ);
    if (blockIndex == -1) {
        if (state->motionFlags & GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT) {
            state->detonationTrigger = GUNPOWDER_BARREL_DETONATION_TRIGGER_IMPACT;
        }
        return;
    }
    if (state->detonationTrigger == 0 &&
        ((state->motionFlags & GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT) || state->throwVelocityY > 0.01f)) {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, GUNPOWDER_BARREL_HIT_VOLUME_SLOT_BODY, 1, 0);
        ObjHits_EnableObject(obj);
    }
    if (!state->heldFlags.playerHeld) {
        state->throwVelocityY -= 0.12f * timeDelta;
    }
    {
        f32 velX = state->throwVelocityX;
        state->throwVelocityX = (velX < -5.0f) ? -5.0f : ((velX > 5.0f) ? 5.0f : velX);
    }
    {
        f32 velY = state->throwVelocityY;
        state->throwVelocityY = (velY < -5.0f) ? -5.0f : ((velY > 5.0f) ? 5.0f : velY);
    }
    {
        f32 velZ = state->throwVelocityZ;
        state->throwVelocityZ = (velZ < -5.0f) ? -5.0f : ((velZ > 5.0f) ? 5.0f : velZ);
    }
    obj->anim.velocityX = state->throwVelocityX;
    obj->anim.velocityY = state->throwVelocityY;
    obj->anim.velocityZ = state->throwVelocityZ;
    deltaTime = timeDelta;
    objMove(obj, obj->anim.velocityX * deltaTime, obj->anim.velocityY * deltaTime, obj->anim.velocityZ * deltaTime);
    state->heldFlags.onGround = 0;
    if (!(state->motionFlags & GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT)) {
        f32 top;
        f32 bottom;
        int below;
        int result;

        top = obj->anim.previousLocalPosY;
        bottom = obj->anim.localPosY;
        below = top < bottom;
        if (below) {
            bottom += 5.0f;
        }
        if (!below) {
            top += 5.0f;
        }
        result =
            findSurfaceInYRange(obj, obj->anim.localPosX, top, obj->anim.localPosZ, bottom, &surfaceY, &contactObject);
        if (result != 0) {
            if (result == 2) {
                state->detonationTrigger = GUNPOWDER_BARREL_DETONATION_TRIGGER_IMPACT;
            } else {
                if (!state->heldFlags.wasOnGround) {
                    if (state->heldFlags.landed) {
                        Sfx_PlayFromObject(obj, SFXTRIG_barrel_putdown);
                    } else {
                        state->heldFlags.landed = 1;
                    }
                }
                state->heldFlags.onGround = 1;
                obj->anim.localPosY = surfaceY;
            }
        }
    }
    if (state->heldFlags.onGround) {
        f32 z = 0.0f;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
        state->throwVelocityX = z;
        state->throwVelocityY = z;
        state->throwVelocityZ = z;
        if (contactObject != 0) {
            u32 flags;
            ObjHits_AddContactObject(contactObject, obj);
            flags = contactObject->anim.modelInstance->flags;
            if ((flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) && !(flags & 0x8000)) {
                state->queuedHitObject = contactObject;
            } else if (state->accumulatedFallVelocity < -100.0f) {
                state->detonationTrigger = GUNPOWDER_BARREL_DETONATION_TRIGGER_IMPACT;
            }
        }
        if (state->heldFlags.playerHeld) {
            gunpowderBarrel_setPlayerHeldState(obj, 0);
        }
        state->accumulatedFallVelocity = 0.0f;
    } else {
        if (state->throwVelocityY < -0.2f) {
            gunpowderBarrel_homeOnTarget(obj, state->homingHeadingA, state->homingHeadingB);
        }
        if (!state->heldFlags.held && !state->heldFlags.playerHeld) {
            state->accumulatedFallVelocity += obj->anim.velocityY;
            if (state->accumulatedFallVelocity < -gGunpowderBarrelFallDetonationThreshold) {
                state->detonationTrigger = GUNPOWDER_BARREL_DETONATION_TRIGGER_IMPACT;
            }
        }
    }
    state->heldFlags.wasOnGround = state->heldFlags.onGround;
}

int gunpowderBarrel_getExtraSize(void) {
    return sizeof(GunpowderBarrelState);
}

void gunpowderBarrel_free(GameObject* obj, int keepLinkedTimer) {
    GunpowderBarrelState* state;
    void* linkedTimer;
    state = obj->extra;
    (*gCarryableInterface)->free(obj);
    linkedTimer = state->linkedTimerObject;
    if (linkedTimer != NULL && keepLinkedTimer == 0) {
        if (Obj_IsObjectAlive((GameObject*)linkedTimer) != 0) {
            ObjLink_DetachChild(obj, state->linkedTimerObject);
            state->linkedTimerObject = NULL;
        }
    }
    objFreeObjectType(obj, GUNPOWDER_BARREL_OBJECT_GROUP);
    objFreeObjectType(obj, GUNPOWDER_BARREL_LOOSE_OBJECT_GROUP);
    if (state->fuseFrames != 0) {
        (*gExpgfxInterface)->freeSource2((u32)obj);
    }
}

void gunpowderBarrel_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    GunpowderBarrelState* state;
    int renderResult;
    GameObject* linkedTimer;

    state = obj->extra;
    if (state->fuseFrames != 0 || state->heldFlags.held) {
        return;
    }
    if (state->heldByCarryInterface != 0) {
        obj->anim.rotZ = 0;
        obj->anim.rotY = 0;
    }
    renderResult = (*gCarryableInterface)->updateRenderState(obj, visible);
    if (renderResult != 0 || visible == -1) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
    linkedTimer = state->linkedTimerObject;
    if (linkedTimer != 0) {
        (*(GunpowderBarrelTimerInterface**)linkedTimer->anim.dll)
            ->render((GameObject*)linkedTimer, renderArg2, renderArg3, renderArg4, renderArg5, visible);
    }
}

void gunpowderBarrel_hitDetect(GameObject* barrel) {
    GunpowderBarrelState* state;
    f32 capturedVelocity[3];
    f32 collisionNormal[3];
    GunpowderBarrelCollisionScratch collision;

    state = barrel->extra;

    if (Obj_IsObjectAlive(state->linkedTimerObject) == 0) {
        if (state->linkedTimerObject != NULL) {
            ObjLink_DetachChild(barrel, state->linkedTimerObject);
            state->linkedTimerObject = NULL;
        }
    }

    if (state->fuseFrames != 0u) {
        return;
    }

    if (timerIsActive(&state->respawnTimer) != 0) {
        return;
    }
    switch (timerIsActive(&state->releaseTimer)) {
    case 0:
        break;
    default:
        return;
    }

    if (state->queuedHitObject != NULL) {
        Obj_SetParent(barrel, state->queuedHitObject, 1);
        state->queuedHitObject = NULL;
    }

    if (state->heldFlags.playerHeld != 0) {
        capturedVelocity[0] = barrel->anim.localPosX - barrel->anim.previousLocalPosX;
        capturedVelocity[1] = barrel->anim.localPosY - barrel->anim.previousLocalPosY;
        capturedVelocity[2] = barrel->anim.localPosZ - barrel->anim.previousLocalPosZ;
        {
            f32 inverseDeltaTime = 0.99f * oneOverTimeDelta;
            capturedVelocity[0] = capturedVelocity[0] * inverseDeltaTime;
            capturedVelocity[1] = capturedVelocity[1] * inverseDeltaTime;
            capturedVelocity[2] = capturedVelocity[2] * inverseDeltaTime;
        }
        state->throwVelocityX = ((f32*)capturedVelocity)[0] + state->throwVelocityX;
        state->throwVelocityY = ((f32*)capturedVelocity)[1] + state->throwVelocityY;
        state->throwVelocityZ = ((f32*)capturedVelocity)[2] + state->throwVelocityZ;
        {
            f32 zero = 0.0f;
            capturedVelocity[1] = zero;
            state->throwVelocityX = 0.5f * state->throwVelocityX;
            state->throwVelocityY = 0.5f * state->throwVelocityY;
            state->throwVelocityZ = 0.5f * state->throwVelocityZ;
            state->throwVelocityY = zero;
        }
        state->motionFlags = state->motionFlags | GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING;
    }

    if (state->heldByCarryInterface == 0 &&
        trackGetLineIntersect(&barrel->anim.previousLocalPosX, &barrel->anim.localPosX, 8.0f, 1, &collision.hit,
                           barrel, 8, -1, 0xff, 0) != 0) {
        if (collision.hit.kind == 0x14) {
            state->detonationTrigger = GUNPOWDER_BARREL_DETONATION_TRIGGER_IMPACT;
        }

        if (state->heldFlags.playerHeld != 0 && collision.hit.kind == 3) {
            gunpowderBarrel_setPlayerHeldState(barrel, 0);
            objFreeObjectType(barrel, GUNPOWDER_BARREL_LOOSE_OBJECT_GROUP);
        } else {
            collisionNormal[0] = collision.hit.normalX;
            collisionNormal[1] = collision.hit.normalY;
            collisionNormal[2] = collision.hit.normalZ;
            Vec3_ReflectAgainstNormal(collisionNormal, &barrel->anim.velocityX, &barrel->anim.velocityX);
            Vec3_ReflectAgainstNormal(collisionNormal, &state->throwVelocityX, &state->throwVelocityX);

            {
                f32 damping = 0.2f;
                barrel->anim.velocityX = damping * barrel->anim.velocityX;
                barrel->anim.velocityY = damping * barrel->anim.velocityY;
                barrel->anim.velocityZ = damping * barrel->anim.velocityZ;
                state->throwVelocityX = damping * state->throwVelocityX;
                state->throwVelocityY = damping * state->throwVelocityY;
                state->throwVelocityZ = damping * state->throwVelocityZ;
            }

            if (state->impactSoundCooldown > 60.0f) {
                if (PSVECMag(&state->throwVelocity) > gGunpowderBarrelImpactSoundSpeedThreshold) {
                    Sfx_PlayFromObject(barrel, SFXTRIG_statue_waterfall);
                }
                state->impactSoundCooldown = 0.0f;
            }
        }
    }

    barrel->anim.previousLocalPosX = barrel->anim.localPosX;
    barrel->anim.previousLocalPosY = barrel->anim.localPosY;
    barrel->anim.previousLocalPosZ = barrel->anim.localPosZ;
}

void gunpowderBarrel_update(GameObject* obj) {
    GunpowderBarrelState* state = obj->extra;
    GameObject* player;
    GunpowderBarrelPlacement* placement;
    player = Obj_GetPlayerObject();
    placement = (GunpowderBarrelPlacement*)obj->anim.placement;

    if (state->impactSoundCooldown <= 60.0f) {
        state->impactSoundCooldown += timeDelta;
    }
    /* Respawn after the hidden timer expires. */
    if (timerIsActive(&state->respawnTimer) != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (timerCountDown(&state->respawnTimer) != 0) {
            state->fuseFrames = 0;
            state->detonationTrigger = 0;
            state->motionFlags |= GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING;
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
            ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, 8, -2, 0x19);
            ObjHits_EnableObject(obj);
            ObjHits_SyncObjectPositionIfDirty(obj);
            gunpowderBarrel_updatePhysics(obj);
            gunpowderBarrel_setPlayerHeldState(obj, 0);
        }
        return;
    }
    /* Hold still during the generator release cooldown. */
    if (timerIsActive(&state->releaseTimer) != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        timerCountDown(&state->releaseTimer);
        memset(&state->throwVelocityX, 0, 0xc);
        memset((void*)&obj->anim.velocityX, 0, 0xc);
        return;
    }
    if (state->heldFlags.held == 0) {
        if (state->heldFlags.cannonRangeVariant != 0 && playerIsDisguised(player) == 0) {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        } else {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
    if (obj->childObjs[0] == NULL) {
        f32 timerRange = 50.0f;
        if ((u32)(state->linkedTimerObject =
                      objGetNearestTypeTo(TIMER_OBJECT_GROUP, obj, &timerRange)) != 0 &&
            timer_isEffectMode(state->linkedTimerObject) != 0 && state->linkedTimerObject->ownerObj == NULL) {
            ObjLink_AttachChild(obj, state->linkedTimerObject, 0);
        }
    } else if (Obj_IsObjectAlive(state->linkedTimerObject) == 0 && state->linkedTimerObject != NULL) {
        ObjLink_DetachChild(obj, state->linkedTimerObject);
        state->linkedTimerObject = NULL;
    }
    {
        u32 messageArgument;
        u32 message;
        message = 0;
        messageArgument = 0;
        while (ObjMsg_Pop(obj, &message, 0, &messageArgument) != 0) {
            switch (message) {
            case GUNPOWDER_BARREL_MESSAGE_PLAYER_HELD:
                gunpowderBarrel_setPlayerHeldState(obj, 1);
                break;
            case GUNPOWDER_BARREL_MESSAGE_PLAYER_RELEASED:
                gunpowderBarrel_setPlayerHeldState(obj, 0);
                if (messageArgument != 0) {
                    objAddObjectType(obj, GUNPOWDER_BARREL_LOOSE_OBJECT_GROUP);
                }
                break;
            }
        }
    }
    if (state->heldFlags.held != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    } else {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    }
    /* Grow the blast hitbox until the fuse completes. */
    if (state->fuseFrames != 0) {
        state->fuseFrames += framesThisStep;
        state->hitRadius = state->radiusGrowthPerFrame * (f32)(u32)state->fuseFrames + 1.0f;
        {
            f32 r = state->hitRadius;
            ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, r, (s32)(-r / 2.0f), (s32)(r / 2.0f));
        }
        if (state->linkedTimerObject != NULL) {
            timer_clearManualFlags(state->linkedTimerObject);
        }
        if (state->fuseFrames > GUNPOWDER_BARREL_FUSE_DURATION_FRAMES) {
            int index;
            u32* generators;
            GameObject* generator;
            if (state->heldFlags.playerHeld != 0) {
                gunpowderBarrel_setPlayerHeldState(obj, 0);
            }
            generator = 0;
            if (placement->generatorLinkId != 0) {
                int generatorCount;
                u32* generatorIter;
                generators = (u32*)objGetAllOfType(BARREL_GENERATOR_OBJECT_GROUP, &generatorCount);
                index = 0;
                generatorIter = generators;
                for (; index < generatorCount; index++) {
                    if (placement->generatorLinkId == barrelgener_getLinkId((GameObject*)(*generatorIter))) {
                        generator = (GameObject*)generators[index];
                        break;
                    }
                    generatorIter++;
                }
            } else {
                generator = objGetNearestTypeTo(BARREL_GENERATOR_OBJECT_GROUP, obj, 0);
            }
            if (generator == NULL) {
                Obj_RemoveFromUpdateList(obj);
                ObjHits_DisableObject(obj);
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                s16toFloat(&state->respawnTimer, GUNPOWDER_BARREL_RESPAWN_DURATION_FRAMES);
                return;
            }
            memset(&state->throwVelocityX, 0, 0xc);
            memset((void*)&obj->anim.velocityX, 0, 0xc);
            state->motionFlags &= ~GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT;
            ObjHits_RefreshObjectState(obj);
            if (state->configFlags.respawns != 0) {
                s16toFloat(&state->respawnTimer, GUNPOWDER_BARREL_RESPAWN_DURATION_FRAMES);
                storeZeroToFloatParam(&state->releaseTimer);
                s16toFloat(&state->releaseTimer, GUNPOWDER_BARREL_RELEASE_DURATION_FRAMES);
                barrelgener_queueObjectRelease(generator, obj, GUNPOWDER_BARREL_GENERATOR_RELEASE_FRAME);
                ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
                ObjHits_DisableObject(obj);
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                return;
            }
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        return;
    }
    if (state->heldByCarryInterface != 0) {
        if ((playerGetStateFlag310(player) & PLAYER_STATE_FLAG_CAN_PLACE_CARRYABLE) != 0) {
            setAButtonIcon(A_BUTTON_ICON_PLACE_CARRYABLE);
        } else {
            setAButtonIcon(A_BUTTON_ICON_THROW_CARRYABLE);
        }
    } else if (state->configFlags.returnHome != 0 && state->heldFlags.onGround != 0 &&
               (state->motionFlags & GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT) == 0) {
        saveGame_saveObjectPos(obj);
    }
    if ((state->motionFlags & GUNPOWDER_BARREL_MOTION_FLAG_IN_FLIGHT) != 0 || state->heldFlags.held != 0 ||
        (*gCarryableInterface)->updateHeld(obj, state) == 0 ||
        (state->heldFlags.cannonRangeVariant != 0 && playerIsDisguised(player) == 0)) {
        ObjHits_EnableObject(obj);
        gunpowderBarrel_triggerExplosion(obj);
        obj->anim.alpha = GUNPOWDER_BARREL_MAX_ALPHA;
        if (state->heldByCarryInterface != 0) {
            state->heldByCarryInterface = 0;
            if (playerIsPuttingDown(player) != 0) {
                /* Set down in place. */
                ObjHits_SyncObjectPositionIfDirty(obj);
            } else if (playerIsThrowing(player) != 0) {
                /* Launch at the selected target. */
                ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
                gunpowderBarrel_launchAtTarget(obj, 1);
            } else if (0.0f == playerGetVerticalVel(player)) {
                /* Release without lift as a gentle toss. */
                ObjHits_SyncObjectPositionIfDirty(obj);
                gunpowderBarrel_launchAtTarget(obj, 0);
            } else if (state->fuseFrames == 0) {
                obj->anim.velocityX = state->throwVelocityX = mathSinf(3.1415927f * (f32)player->anim.rotX / 32768.0f);
                obj->anim.velocityY = state->throwVelocityY = 0.0f;
                obj->anim.velocityZ = state->throwVelocityZ = mathCosf(3.1415927f * (f32)player->anim.rotX / 32768.0f);
                obj->anim.localPosX =
                    gGunpowderBarrelReleaseOffset * -mathSinf(3.1415927f * (f32)player->anim.rotX / 32768.0f) +
                    obj->anim.localPosX;
                obj->anim.localPosZ =
                    gGunpowderBarrelReleaseOffset * -mathCosf(3.1415927f * (f32)player->anim.rotX / 32768.0f) +
                    obj->anim.localPosZ;
                objAddObjectType(obj, GUNPOWDER_BARREL_LOOSE_OBJECT_GROUP);
            }
            /* Re-register after every release transition. */
            objAddObjectType(obj, GUNPOWDER_BARREL_LOOSE_OBJECT_GROUP);
        }
        gunpowderBarrel_updatePhysics(obj);
    } else {
        state->motionFlags |= GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING;
        if (state->heldByCarryInterface == 0) {
            if (state->linkedTimerObject != NULL) {
                timer_forceStart(state->linkedTimerObject);
            }
            objFreeObjectType(obj, GUNPOWDER_BARREL_LOOSE_OBJECT_GROUP);
        }
        state->heldByCarryInterface = 1;
        state->heldFlags.pendingThrowVelocityCapture = 1;
        state->launchYaw = player->anim.rotX;
        gunpowderBarrel_triggerExplosion(obj);
    }
    if (state->heldFlags.playerHeld != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (state->heldFlags.pendingThrowVelocityCapture != 0 && state->heldFlags.playerHeld != 0) {
            state->throwVelocityX = obj->anim.velocityX;
            state->throwVelocityY = obj->anim.velocityY;
            state->throwVelocityZ = obj->anim.velocityZ;
            state->throwVelocityY = 0.0f;
            state->heldFlags.pendingThrowVelocityCapture = 0;
        }
    }
    if (state->linkedTimerObject != NULL) {
        if (timer_hasExpired(state->linkedTimerObject) != 0) {
            state->detonationTrigger = GUNPOWDER_BARREL_DETONATION_TRIGGER_TIMER;
        }
    }
}

void gunpowderBarrel_init(GameObject* obj, GunpowderBarrelPlacement* placement) {
    GunpowderBarrelState* state = obj->extra;

    ((GunpowderBarrelState*)obj->extra)->unknown07 |= 2;
    (*gCarryableInterface)->init(obj, state, GUNPOWDER_BARREL_CARRYABLE_MODE);
    objAddObjectType(obj, GUNPOWDER_BARREL_OBJECT_GROUP);
    objAddObjectType(obj, GUNPOWDER_BARREL_LOOSE_OBJECT_GROUP);
    ObjMsg_AllocQueue(obj, GUNPOWDER_BARREL_MESSAGE_QUEUE_CAPACITY);
    obj->userData2 = 0;
    state->homingHeadingA = 0;
    state->homingHeadingB = 0;
    state->heldByCarryInterface = 0;
    state->unknown3C = 0;
    state->detonationTrigger = 0;
    state->fuseFrames = 0;
    state->unknown3E = 0;
    state->unknown40 = 0;
    state->unknown30 = 0.0f;
    state->motionFlags = 0;
    storeZeroToFloatParam(&state->respawnTimer);
    storeZeroToFloatParam(&state->releaseTimer);
    state->motionFlags |= GUNPOWDER_BARREL_MOTION_FLAG_SLEEPING;
    {
        u8 configFlag;
        configFlag = (placement->disableRespawn >= 1) ? 0 : 1;
        state->configFlags.respawns = configFlag;
        configFlag = (placement->returnHome == 0) ? 0 : 1;
        state->configFlags.returnHome = configFlag;
    }
    ObjHits_EnableObject(obj);
    state->hitRadius = (f32)((ObjHitsPriorityState*)obj->anim.hitReactState)->primaryRadius;
    state->heldFlags.held = 0;
    state->accumulatedFallVelocity = 0.0f;
    state->linkedTimerObject = NULL;
    (*gCarryableInterface)->setSuppressPositionSave(state, 1);
    if ((ObjHitsPriorityState*)obj->anim.hitReactState != NULL) {
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->trackContactMask = 1;
    }
    if (obj->anim.romDefNo == GUNPOWDER_BARREL_SEQUENCE_CANNON_RANGE) {
        state->heldFlags.cannonRangeVariant = 1;
    }
}

ObjectDescriptor11WithPadding gGunpowderBarrelObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        0,
        0,
        0,
        (ObjectDescriptorCallback)gunpowderBarrel_init,
        (ObjectDescriptorCallback)gunpowderBarrel_update,
        (ObjectDescriptorCallback)gunpowderBarrel_hitDetect,
        (ObjectDescriptorCallback)gunpowderBarrel_render,
        (ObjectDescriptorCallback)gunpowderBarrel_free,
        0,
        gunpowderBarrel_getExtraSize,
        (ObjectDescriptorCallback)gunpowderBarrel_addThrowVelocity,
    },
    0,
};
