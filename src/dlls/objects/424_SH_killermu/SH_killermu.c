/*
 * SH_killermu (DLL 0x1A8) - the large red poisonous mushroom enemy
 * rooted in the ground in ThornTail Hollow. It remains stationary; when the
 * player runs close it shakes in place and spreads a growing
 * cloud of poison that damages anyone inside its radius. Striking it knocks it
 * into a cartoonish side-to-side stun during which it deals no damage, then it
 * recovers.
 *
 * Its main cycle is idle -> startled -> poisoning -> settling. Shared
 * mushroom states also handle regrowth, fading, deflation, stun recovery, and
 * delayed respawning. The player can avoid waking an idle mushroom by moving
 * slowly through its detection radius.
 */
#include "dlls/objects/424_SH_killermu.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/player_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/obj_path.h"
#include "main/objtype.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define ENEMY_MUSHROOM_OBJECT_GROUP 3

#define ENEMY_MUSHROOM_PARTICLE_EFFECT_HIT  0x3EB
#define ENEMY_MUSHROOM_PARTICLE_EFFECT_STUN 0x51D

#define ENEMY_MUSHROOM_CONTACT_HIT_TYPE        0x16
#define ENEMY_MUSHROOM_MODEL_FLAGS             0x810
#define ENEMY_MUSHROOM_MIN_RESPAWN_FRAME_LIMIT 0x708

#define ENEMY_MUSHROOM_RISE_STEP_EPSILON          0.00001f
#define ENEMY_MUSHROOM_RISE_DURATION_BASE         200.0f
#define ENEMY_MUSHROOM_HEIGHT_TARGET_JITTER       0.001f
#define ENEMY_MUSHROOM_HIT_EFFECT_SCALE           0.014f
#define ENEMY_MUSHROOM_DEFLATE_RADIUS_RATE        3.5f
#define ENEMY_MUSHROOM_MAX_HIT_RADIUS             80.0f
#define ENEMY_MUSHROOM_POISON_RADIUS_RATE         2.5f
#define ENEMY_MUSHROOM_POISON_DURATION            120.0f
#define ENEMY_MUSHROOM_RISE_STEP_DECAY            1.1f
#define ENEMY_MUSHROOM_STUN_EFFECT_INTERVAL       20.0f
#define ENEMY_MUSHROOM_DETECT_RANGE_SCALE         1.5f
#define ENEMY_MUSHROOM_TRIGGER_ANIM_SPEED         0.54f
#define ENEMY_MUSHROOM_STUN_ANIM_PROGRESS_DIVISOR 100.0f
#define ENEMY_MUSHROOM_SPAWN_Y_OFFSET             2.0f

typedef struct EnemyMushroomHitInfo {
    f32 particleParams[3];
    f32 x;
    f32 y;
    f32 z;
} EnemyMushroomHitInfo;

STATIC_ASSERT(sizeof(EnemyMushroomHitInfo) == 0x18);
STATIC_ASSERT(offsetof(EnemyMushroomHitInfo, x) == 0x0C);
STATIC_ASSERT(offsetof(EnemyMushroomHitInfo, y) == 0x10);
STATIC_ASSERT(offsetof(EnemyMushroomHitInfo, z) == 0x14);

void EnemyMushroom_resetToSpawn(GameObject* obj, EnemyMushroomState* state, int enableTimer) {
    EnemyMushroomPlacement* placement;
    u32 randomValue;
    f32 randomizedValue;

    placement = (EnemyMushroomPlacement*)obj->anim.placementData;
    obj->anim.rotZ = randomGetRange(-0x5DC, 0x5DC);
    obj->anim.rotY = randomGetRange(-0x5DC, 0x5DC);
    obj->anim.rotX = randomGetRange(-0x5DC, 0x5DC);
    obj->anim.alpha = 0xFF;
    obj->anim.flags = (s16)(obj->anim.flags & ~OBJANIM_FLAG_HIDDEN);
    obj->anim.localPosX = placement->base.posX;
    obj->anim.localPosY = placement->base.posY;
    obj->anim.localPosZ = placement->base.posZ;
    if (enableTimer != 0) {
        obj->anim.rootMotionScale = ENEMY_MUSHROOM_RISE_STEP_EPSILON;
        state->timer = 0.0f;
        randomValue = randomGetRange(0, 100);
        randomizedValue = (f32)(s32)randomValue;
        randomizedValue = ENEMY_MUSHROOM_RISE_DURATION_BASE + randomizedValue;
        state->riseDuration = randomizedValue;
        randomValue = randomGetRange(-100, 100);
        randomizedValue = (f32)(s32)randomValue;
        randomizedValue = ENEMY_MUSHROOM_HEIGHT_TARGET_JITTER * randomizedValue + state->baseScale;
        state->heightTarget = randomizedValue;
        state->riseStep = state->heightTarget / state->riseDuration;
    }
    ObjHits_EnableObject(obj);
    ObjHits_RefreshObjectState(obj);
}

int EnemyMushroom_getExtraSize(void) {
    return sizeof(EnemyMushroomState);
}

int EnemyMushroom_getObjectTypeId(GameObject* obj) {
    EnemyMushroomPlacement* placement = (EnemyMushroomPlacement*)obj->anim.placementData;

    return (placement->objectTypeParam << 11) | 0x400;
}

void EnemyMushroom_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource((u32)obj);
    objFreeObjectType(obj, ENEMY_MUSHROOM_OBJECT_GROUP);
}

void EnemyMushroom_render(GameObject* obj, u32 flags, u32 texData, u32 colorTable, u32 modelState, char visible) {
    EnemyMushroomState* state = obj->extra;
    f32 scale = 1.0f;

    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, flags, texData, colorTable, modelState, scale);
        ObjPath_GetPointWorldPosition(obj, 0, &state->hitEffectX, &state->hitEffectY, &state->hitEffectZ, 0);
    }
}

void EnemyMushroom_hitDetect(void) {
}

s16 gEnemyMushroomStateAnimMoves[ENEMY_MUSHROOM_STATE_ANIM_MOVE_COUNT] = {0, 0, 4, 1, 2, 3, 5, 6, 6, 6, 0, 0};
f32 gEnemyMushroomStateAnimRates[ENEMY_MUSHROOM_STATE_ANIM_RATE_COUNT] = {
    0.0f, 0.0f, 0.008f, 0.025f, 0.018f, 0.015f, 0.006f, 0.008f, 0.005f, 0.005f, 0.005f,
};
ObjectDescriptor gEnemyMushroomObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)EnemyMushroom_initialise,
    (ObjectDescriptorCallback)EnemyMushroom_release,
    0,
    (ObjectDescriptorCallback)EnemyMushroom_init,
    (ObjectDescriptorCallback)EnemyMushroom_update,
    (ObjectDescriptorCallback)EnemyMushroom_hitDetect,
    (ObjectDescriptorCallback)EnemyMushroom_render,
    (ObjectDescriptorCallback)EnemyMushroom_free,
    (ObjectDescriptorCallback)EnemyMushroom_getObjectTypeId,
    EnemyMushroom_getExtraSize,
};

/* Per-frame poison, hit-reaction, fade, and respawn state machine. */
void EnemyMushroom_update(GameObject* obj) {
    EnemyMushroomState* state;
    GameObject* player;
    EnemyMushroomPlacement* placement;
    EnemyMushroomHitInfo hitInfo;
    GameObject* hitObject;
    int hitSphereIndex;
    u32 hitVolume;
    int hitType;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    placement = (EnemyMushroomPlacement*)obj->anim.placementData;
    ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    state->stateFlags |= ENEMY_MUSHROOM_STATE_FLAG_ACTIVE;

    if (objIsFrozen(obj)) {
        hitType = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume, &hitInfo.x,
                                                     &hitInfo.y, &hitInfo.z);
        if (hitType != 0 && hitType != OBJHITS_SHAPE_MODEL_HIT_VOLUMES) {
            hitInfo.x += playerMapOffsetX;
            hitInfo.z += playerMapOffsetZ;
            objDoHitParticleFx(obj, ENEMY_MUSHROOM_HIT_EFFECT_SCALE, &hitInfo, 1, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_barrel_bounce1);
            Obj_Shatter(obj);
        }
        return;
    }

    if (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) {
        return;
    }

    switch (state->stateId) {
    case ENEMY_MUSHROOM_STATE_DEFLATING:
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_diallp_c);
        state->stateFlags = (u8)(state->stateFlags & ~ENEMY_MUSHROOM_STATE_FLAG_ACTIVE);
        state->hitRadius = ENEMY_MUSHROOM_DEFLATE_RADIUS_RATE * timeDelta + state->hitRadius;
        if (state->hitRadius > ENEMY_MUSHROOM_MAX_HIT_RADIUS) {
            state->hitRadius = ENEMY_MUSHROOM_MAX_HIT_RADIUS;
        }
        if (!(state->stateFlags & ENEMY_MUSHROOM_STATE_FLAG_HIT_PLAYER)) {
            if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) <= state->hitRadius &&
                !EmissionController_IsLingering(player) && !playerGetFlags3F0Bit5(player) &&
                !(player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK)) {
                ObjHits_RecordObjectHit(player, obj, ENEMY_MUSHROOM_CONTACT_HIT_TYPE, 1, 0);
                state->stateFlags |= ENEMY_MUSHROOM_STATE_FLAG_HIT_PLAYER;
            }
        }
        if (state->stateFlags & ENEMY_MUSHROOM_STATE_FLAG_ANIM_DONE) {
            state->timer = 0.0f;
            state->stateId = ENEMY_MUSHROOM_STATE_FADING;
        }
        hitInfo.x = state->hitEffectX;
        hitInfo.y = state->hitEffectY;
        hitInfo.z = state->hitEffectZ;
        {
            u8 particleCount = 1;
            int particleFlags = 0x200000;
            while (particleCount != 0) {
                (*gPartfxInterface)
                    ->spawnObject(obj, ENEMY_MUSHROOM_PARTICLE_EFFECT_HIT, &hitInfo, particleFlags + 1, -1, NULL);
                particleCount--;
            }
        }
        break;
    case ENEMY_MUSHROOM_STATE_FADING:
        state->stateFlags = (u8)(state->stateFlags & ~ENEMY_MUSHROOM_STATE_FLAG_ACTIVE);
        if (state->stateFlags & ENEMY_MUSHROOM_STATE_FLAG_ANIM_DONE) {
            int newAlpha = obj->anim.alpha - framesThisStep * 4;
            if (newAlpha < 0) {
                newAlpha = 0;
            }
            obj->anim.alpha = newAlpha;
            state->timer += timeDelta;
            if (state->timer > (f32)state->respawnFrameLimit) {
                EnemyMushroom_resetToSpawn(obj, state, 1);
                state->stateId = ENEMY_MUSHROOM_STATE_REGROWING;
            }
        }
        break;
    case ENEMY_MUSHROOM_STATE_STARTLED:
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_id_9c);
        if (state->stateFlags & ENEMY_MUSHROOM_STATE_FLAG_ANIM_DONE) {
            state->stateId = ENEMY_MUSHROOM_STATE_POISONING;
        }
        break;
    case ENEMY_MUSHROOM_STATE_POISONING:
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        state->hitRadius = ENEMY_MUSHROOM_POISON_RADIUS_RATE * timeDelta + state->hitRadius;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_diallp_c);
        if (!(state->stateFlags & ENEMY_MUSHROOM_STATE_FLAG_HIT_PLAYER)) {
            if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) <= state->hitRadius &&
                !EmissionController_IsLingering(player) && !playerGetFlags3F0Bit5(player) &&
                !(player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK)) {
                ObjHits_RecordObjectHit(player, obj, ENEMY_MUSHROOM_CONTACT_HIT_TYPE, 1, 0);
                state->stateFlags |= ENEMY_MUSHROOM_STATE_FLAG_HIT_PLAYER;
            }
        }
        if (state->hitRadius > ENEMY_MUSHROOM_MAX_HIT_RADIUS) {
            state->hitRadius = ENEMY_MUSHROOM_MAX_HIT_RADIUS;
        }
        state->timer += timeDelta;
        if (state->timer > ENEMY_MUSHROOM_POISON_DURATION) {
            state->timer = 0.0f;
            state->stateId = ENEMY_MUSHROOM_STATE_SETTLING;
        }
        hitInfo.x = state->hitEffectX;
        hitInfo.y = state->hitEffectY;
        hitInfo.z = state->hitEffectZ;
        {
            u8 particleCount = 1;
            int particleFlags = 0x200000;
            while (particleCount != 0) {
                (*gPartfxInterface)
                    ->spawnObject(obj, ENEMY_MUSHROOM_PARTICLE_EFFECT_HIT, &hitInfo, particleFlags + 1, -1, NULL);
                particleCount--;
            }
        }
        break;
    case ENEMY_MUSHROOM_STATE_SETTLING:
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        state->timer += timeDelta;
        if (state->timer > (f32)placement->regrowDelay) {
            if (state->stateFlags & ENEMY_MUSHROOM_STATE_FLAG_ANIM_DONE) {
                state->stateId = ENEMY_MUSHROOM_STATE_IDLE;
                state->hitRadius = 0.0f;
                state->stateFlags = (u8)(state->stateFlags & ~ENEMY_MUSHROOM_STATE_FLAG_HIT_PLAYER);
            }
        }
        break;
    case ENEMY_MUSHROOM_STATE_REGROWING:
        state->stateFlags = (u8)(state->stateFlags & ~ENEMY_MUSHROOM_STATE_FLAG_ACTIVE);
        if (obj->anim.rootMotionScale > state->heightTarget) {
            state->riseStep /= ENEMY_MUSHROOM_RISE_STEP_DECAY;
        }
        if (state->riseStep < ENEMY_MUSHROOM_RISE_STEP_EPSILON) {
            state->riseStep = 0.0f;
        }
        state->timer += timeDelta;
        obj->anim.rootMotionScale = state->riseStep * timeDelta + obj->anim.rootMotionScale;
        if (state->timer > state->riseDuration) {
            state->stateId = ENEMY_MUSHROOM_STATE_IDLE;
        }
        break;
    case ENEMY_MUSHROOM_STATE_STUNNED:
        if (state->timer <= 0.0f) {
            state->timer = (f32)(int)randomGetRange(0xF0, 0x12C);
        }
        if (state->stateFlags & ENEMY_MUSHROOM_STATE_FLAG_ANIM_DONE) {
            state->timer = 0.0f;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_cagelp_c);
        {
            f32 timer = state->timer - timeDelta;
            state->timer = timer;
            if (timer <= 0.0f) {
                (*gExpgfxInterface)->freeSource((u32)obj);
                state->stateId = ENEMY_MUSHROOM_STATE_IDLE;
                Obj_ResetActiveHitVolumeBounds(obj);
            } else {
                f32 effectTimer = state->effectTimer - timeDelta;
                state->effectTimer = effectTimer;
                if (effectTimer <= 0.0f) {
                    hitInfo.x = 14.0f;
                    hitInfo.y = 25.0f;
                    (*gPartfxInterface)->spawnObject(obj, ENEMY_MUSHROOM_PARTICLE_EFFECT_STUN, &hitInfo, 2, -1, NULL);
                    state->effectTimer = ENEMY_MUSHROOM_STUN_EFFECT_INTERVAL;
                }
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            }
        }
        break;
    case ENEMY_MUSHROOM_STATE_RESPAWN_WAIT:
        ObjHits_DisableObject(obj);
        state->timer += timeDelta;
        if (state->timer > (f32)state->respawnFrameLimit) {
            EnemyMushroom_resetToSpawn(obj, state, 1);
            state->stateId = ENEMY_MUSHROOM_STATE_REGROWING;
            Obj_ResetActiveHitVolumeBounds(obj);
        }
        break;
    default:
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        {
            f32 dx = player->anim.localPosX - obj->anim.localPosX;
            f32 dy = player->anim.localPosY - obj->anim.localPosY;
            f32 dz = player->anim.localPosZ - obj->anim.localPosZ;
            if ((u16)(int)sqrtf(dx * dx + dy * dy + dz * dz) <
                (u16)(int)(ENEMY_MUSHROOM_DETECT_RANGE_SCALE * (f32)placement->detectRange)) {
                if (playerGetAnimSpeed(player) >= ENEMY_MUSHROOM_TRIGGER_ANIM_SPEED) {
                    state->stateFlags = (u8)(state->stateFlags & ~ENEMY_MUSHROOM_STATE_FLAG_HIT_PLAYER);
                    state->stateId = ENEMY_MUSHROOM_STATE_STARTLED;
                    state->timer = 0.0f;
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_haga_talk3);
                }
            }
        }
        break;
    }

    hitType = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume, &hitInfo.x, &hitInfo.y,
                                                 &hitInfo.z);
    hitInfo.x += playerMapOffsetX;
    hitInfo.z += playerMapOffsetZ;
    if (hitType != 0) {
        if (state->stateFlags & ENEMY_MUSHROOM_STATE_FLAG_ACTIVE) {
            if (hitType == OBJHITS_SHAPE_MODEL_HIT_VOLUMES) {
                Obj_StartModelFadeIn(obj, 0x12C);
            } else {
                if (state->stateId != ENEMY_MUSHROOM_STATE_STUNNED) {
                    Sfx_PlayFromObject(obj, SFXTRIG_mv_ladderslide16);
                }
                state->stateFlags = (u8)(state->stateFlags & ~ENEMY_MUSHROOM_STATE_FLAG_HIT_PLAYER);
                if (placement->popGameBit != -1) {
                    mainSetBits(placement->popGameBit, 1);
                }
                state->stateId = ENEMY_MUSHROOM_STATE_STUNNED;
                state->timer = 0.0f;
                obj->anim.currentMoveProgress =
                    (f32)(int)randomGetRange(0, 0x28) / ENEMY_MUSHROOM_STUN_ANIM_PROGRESS_DIVISOR;
            }
            objDoHitParticleFx(obj, ENEMY_MUSHROOM_HIT_EFFECT_SCALE, &hitInfo, 1, 0);
        }
    }

    if (obj->anim.currentMove != gEnemyMushroomStateAnimMoves[state->stateId]) {
        ObjAnim_SetCurrentMove(obj, gEnemyMushroomStateAnimMoves[state->stateId], 0.0f, 0);
    }
    if (ObjAnim_AdvanceCurrentMove(obj, gEnemyMushroomStateAnimRates[state->stateId], timeDelta, NULL) != 0) {
        state->stateFlags |= ENEMY_MUSHROOM_STATE_FLAG_ANIM_DONE;
    } else {
        state->stateFlags = (u8)(state->stateFlags & ~ENEMY_MUSHROOM_STATE_FLAG_ANIM_DONE);
    }
}

/* Constructor: seeds the state block, clamps the regrow period, offsets the
 * spawn height, flags the model, optionally resets to spawn, and registers
 * in object group 3. */
void EnemyMushroom_init(GameObject* obj, EnemyMushroomPlacement* placement, int flags) {
    EnemyMushroomState* state = obj->extra;
    f32 zero = 0.0f;

    state->timer = zero;
    state->hitRadius = zero;
    state->baseScale = obj->anim.rootMotionScale;
    state->respawnFrameLimit = placement->respawnFrameLimit;
    if (state->respawnFrameLimit < ENEMY_MUSHROOM_MIN_RESPAWN_FRAME_LIMIT) {
        state->respawnFrameLimit = ENEMY_MUSHROOM_MIN_RESPAWN_FRAME_LIMIT;
    }
    obj->anim.localPosY = placement->base.posY - ENEMY_MUSHROOM_SPAWN_Y_OFFSET;
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->flags |= ENEMY_MUSHROOM_MODEL_FLAGS;
    }
    if (flags == 0) {
        EnemyMushroom_resetToSpawn(obj, state, 0);
    }
    objAddObjectType(obj, ENEMY_MUSHROOM_OBJECT_GROUP);
}

void EnemyMushroom_release(void) {
}

void EnemyMushroom_initialise(void) {
}
