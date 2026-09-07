/*
 * BombPlant (DLL 0x1A9) - the harvestable bomb-spore plant.
 *
 * A dormant plant waits for its placement game bit or regrow timer, grows to
 * full size, and reacts to suitable hits by exploding. Plants without a game
 * bit release three BombPlantSp objects when they explode.
 */
#include "dlls/objects/425_BombPlant.h"

#include "dlls/objects/426_BombPlantSp.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/shader_api.h"
#include "main/vec_types.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "dlls/objects/196_Tricky.h"
#include "main/objhits.h"

#define BOMB_PLANT_HIT_VOLUME_SLOT 5
#define BOMB_PLANT_SPARK_PARTICLE  0x7F1

#define BOMB_PLANT_RANDOM_TIMER_MIN -0x32
#define BOMB_PLANT_RANDOM_TIMER_MAX 0x32
#define BOMB_PLANT_GROW_DURATION    135.0f
#define BOMB_PLANT_MIN_GROW_SCALE   0.00001f

#define BOMB_PLANT_STATE_ACTIVE    0
#define BOMB_PLANT_STATE_DORMANT   1
#define BOMB_PLANT_STATE_GROWING   2
#define BOMB_PLANT_STATE_EXPLODING 4

/* BombPlantState::flags */
#define BOMB_PLANT_STATE_FLAG_MOVE_ACTIVE  0x1
#define BOMB_PLANT_STATE_FLAG_JUST_ENTERED 0x2

/* BombPlantStateConfig::flags */
#define BOMB_PLANT_CONFIG_CHECK_HITS      0x01
#define BOMB_PLANT_CONFIG_ENABLE_INTERACT 0x02
#define BOMB_PLANT_CONFIG_HIDDEN          0x04
#define BOMB_PLANT_CONFIG_ENABLE_HITS     0x08
#define BOMB_PLANT_CONFIG_USE_HIT_VOLUME  0x10

int BombPlant_animEventCallback(GameObject* obj) {
    BombPlantState* state;

    state = obj->extra;
    if (state->stateIndex != BOMB_PLANT_STATE_ACTIVE) {
        BombPlantPlacement* placement;

        obj->anim.flags = (s16)(obj->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        placement = (BombPlantPlacement*)obj->anim.placementData;
        obj->anim.alpha = 0xFF;
        obj->anim.flags = (s16)(obj->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        obj->anim.localPosX = placement->base.posX;
        obj->anim.localPosY = placement->base.posY;
        obj->anim.localPosZ = placement->base.posZ;
        obj->anim.rootMotionScale = BOMB_PLANT_MIN_GROW_SCALE;
        state->growDuration = BOMB_PLANT_GROW_DURATION;
        state->growStartScale = state->growTargetScale;
        state->growRate = state->growStartScale / state->growDuration;
        state->growTimer = state->growDuration;
        ObjHits_RefreshObjectState(obj);
        state->stateIndex = BOMB_PLANT_STATE_ACTIVE;
        state->flags = (u8)(state->flags | BOMB_PLANT_STATE_FLAG_JUST_ENTERED);
    } else {
        BombPlantPlacement* placement;
        u8 flags;

        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_baddie_eggsnatch_sniff2);
        placement = (BombPlantPlacement*)obj->anim.placementData;
        flags = state->flags;
        if (flags & BOMB_PLANT_STATE_FLAG_JUST_ENTERED) {
            int timerValue;

            state->flags = (u8)(flags & ~BOMB_PLANT_STATE_FLAG_JUST_ENTERED);
            timerValue =
                placement->timerBase + randomGetRange(BOMB_PLANT_RANDOM_TIMER_MIN, BOMB_PLANT_RANDOM_TIMER_MAX);
            state->growTimer = timerValue;
        }
        if (obj->objectFlags & OBJECT_OBJFLAG_RENDERED) {
            (*gPartfxInterface)->spawnObject(obj, BOMB_PLANT_SPARK_PARTICLE, NULL, 2, -1, NULL);
        }
    }
    return 0;
}

const f32 gBombPlantGrowRangeSq[] = {6400.0f};

static inline void BombPlant_tryBeginGrow(GameObject* obj, BombPlantState* state) {
    GameObject* player;
    f32 distanceSquared;

    player = Obj_GetPlayerObject();
    distanceSquared = vec3f_distanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX);

    if (distanceSquared > gBombPlantGrowRangeSq[0]) {
        state->stateIndex = BOMB_PLANT_STATE_GROWING;
        state->flags |= BOMB_PLANT_STATE_FLAG_JUST_ENTERED;
    }
}

void BombPlant_spawnSpore(GameObject* obj, BombPlantState* unusedState) {
    BombPlantSporePlacement* spore;
    BombPlantPlacement* placement;
    u8 canSetupObject;

    (void)unusedState;

    placement = (BombPlantPlacement*)obj->anim.placementData;
    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject > 0) {
        MatrixTransform transform;
        f32 matrix[16];
        f32 offsetZ;
        f32 offsetY;
        f32 offsetX;

        spore =
            (BombPlantSporePlacement*)Obj_AllocObjectSetup(sizeof(BombPlantSporePlacement), BOMB_PLANT_SPORE_OBJECT_ID);
        transform.rotX = obj->anim.rotX;
        transform.rotY = obj->anim.rotY;
        transform.rotZ = obj->anim.rotZ;
        transform.x = 0.0f;
        transform.y = 0.0f;
        transform.z = 0.0f;
        transform.scale = 1.0f;
        setMatrixFromObjectPos(matrix, &transform);
        Matrix_TransformPoint(matrix, 0.0f, 1.0f, 0.0f, &offsetX, &offsetY, &offsetZ);
        transform.x = 26.0f * offsetX;
        transform.y = 26.0f * offsetY;
        transform.z = 26.0f * offsetZ;
        spore->base.posX = obj->anim.localPosX + transform.x;
        spore->base.posY = obj->anim.localPosY + transform.y;
        spore->base.posZ = obj->anim.localPosZ + transform.z;
        spore->base.color[1] = 1;
        spore->base.color[0] = 2;
        spore->spawn.spawnYaw = (s16)((s32)placement->sporeYaw << 8);
        spore->spawn.rotXSeed = obj->anim.rotX;
        objSetupObject(&spore->base, 5, -1, -1, NULL);
    }
}

int BombPlant_getExtraSize(void) {
    return sizeof(BombPlantState);
}

int BombPlant_getObjectTypeId(void) {
    return 0;
}

void BombPlant_free(void) {
}

void BombPlant_render(GameObject* obj, int flags, int texData, int colorTable, int modelState, s8 unusedVisible) {
    (void)unusedVisible;

    objRenderModelAndHitVolumes(obj, flags, texData, colorTable, modelState, 1.0f);
}

void BombPlant_hitDetect(void) {
}

void BombPlant_explode(GameObject* obj, BombPlantStateConfig* unusedConfig, BombPlantState* state) {
    BombPlantPlacement* placement;
    GameObject* tricky;
    s16 gameBit;
    int sporeIndex;

    (void)unusedConfig;

    placement = (BombPlantPlacement*)obj->anim.placementData;
    tricky = getTrickyObject();
    if (tricky != NULL) {
        trickyImpress(tricky);
    }
    Sfx_PlayFromObject(obj, SFXTRIG_bombplant_woompf);
    {
        ObjHitsPriorityState* hitState;

        hitState = ObjAnim_GetPriorityHitState(&obj->anim);
        hitState->flags = (s16)(hitState->flags | OBJHITS_PRIORITY_STATE_POSITION_DIRTY);
    }
    spawnExplosion(obj, 100.0f, 0, 1, 1, 1, 0, 1, 0);
    state->stateIndex = BOMB_PLANT_STATE_DORMANT;
    state->flags = (u8)(state->flags | BOMB_PLANT_STATE_FLAG_JUST_ENTERED);
    gameBit = placement->gameBit;
    if (gameBit != -1) {
        mainSetBits(gameBit, 0);
    } else {
        for (sporeIndex = 0; sporeIndex < 3; sporeIndex++) {
            BombPlant_spawnSpore(obj, state);
        }
    }
}

void BombPlant_update(GameObject* obj) {
    BombPlantState* state;
    BombPlantStateConfig* config;
    BombPlantPlacement* placement;
    BombPlantPlacement* spawnPlacement;
    ObjDef* model;
    s16 gameBit;
    int hitType;
    Vec3f hitPosition;
    Vec3f lightPosition;
    int hitSphereIndex;
    int hitVolume;
    GameObject* hitObject;

    (void)Obj_GetPlayerObject();
    if (objIsFrozen(obj) != 0) {
        return;
    }

    state = obj->extra;
    config = &gBombPlantStateConfigs[state->stateIndex];

    switch (state->stateIndex) {
    case BOMB_PLANT_STATE_DORMANT:
        placement = (BombPlantPlacement*)obj->anim.placementData;
        if ((state->flags & BOMB_PLANT_STATE_FLAG_JUST_ENTERED) != 0) {
            state->flags &= ~BOMB_PLANT_STATE_FLAG_JUST_ENTERED;
            state->growTimer = (f32)(int)placement->growTimer;
        }
        gameBit = placement->gameBit;
        if (gameBit != -1) {
            if (mainGetBit(gameBit) != 0) {
                BombPlant_tryBeginGrow(obj, state);
            }
        } else {
            f32 timer;

            timer = state->growTimer - timeDelta;
            state->growTimer = timer;
            if (timer <= 0.0f) {
                BombPlant_tryBeginGrow(obj, state);
                state->growTimer = 0.0f;
            }
        }
        break;

    case BOMB_PLANT_STATE_GROWING:
        if ((state->flags & BOMB_PLANT_STATE_FLAG_JUST_ENTERED) != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_bombplant_grows);
            state->flags &= ~BOMB_PLANT_STATE_FLAG_JUST_ENTERED;
            spawnPlacement = (BombPlantPlacement*)obj->anim.placementData;
            obj->anim.alpha = 0xFF;
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            obj->anim.localPosX = spawnPlacement->base.posX;
            obj->anim.localPosY = spawnPlacement->base.posY;
            obj->anim.localPosZ = spawnPlacement->base.posZ;
            obj->anim.rootMotionScale = BOMB_PLANT_MIN_GROW_SCALE;
            state->growDuration = BOMB_PLANT_GROW_DURATION;
            state->growStartScale = state->growTargetScale;
            state->growRate = state->growStartScale / state->growDuration;
            state->growTimer = state->growDuration;
            ObjHits_RefreshObjectState(obj);
        }
        if (obj->anim.rootMotionScale > state->growStartScale) {
            state->growRate /= 1.1f;
        }
        if (state->growRate < BOMB_PLANT_MIN_GROW_SCALE) {
            state->growRate = 0.0f;
        }
        obj->anim.rootMotionScale = state->growRate * timeDelta + obj->anim.rootMotionScale;
        {
            f32 timer;

            timer = state->growTimer - timeDelta;
            state->growTimer = timer;
            if (timer < 0.0f) {
                state->stateIndex = BOMB_PLANT_STATE_ACTIVE;
                state->flags |= BOMB_PLANT_STATE_FLAG_JUST_ENTERED;
            }
        }
        break;

    case BOMB_PLANT_STATE_EXPLODING:
        BombPlant_explode(obj, config, state);
        break;

    case BOMB_PLANT_STATE_ACTIVE:
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_baddie_eggsnatch_sniff2);
        /* fall through */
    default:
        placement = (BombPlantPlacement*)obj->anim.placementData;
        if ((state->flags & BOMB_PLANT_STATE_FLAG_JUST_ENTERED) != 0) {
            state->flags &= ~BOMB_PLANT_STATE_FLAG_JUST_ENTERED;
            state->growTimer = (f32)(int)(placement->timerBase +
                                          randomGetRange(BOMB_PLANT_RANDOM_TIMER_MIN, BOMB_PLANT_RANDOM_TIMER_MAX));
        }
        if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
            (*gPartfxInterface)->spawnObject(obj, BOMB_PLANT_SPARK_PARTICLE, NULL, 2, -1, NULL);
        }
        break;
    }

    if ((config->flags & BOMB_PLANT_CONFIG_CHECK_HITS) != 0) {
        hitType = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, (u32*)&hitVolume, &hitPosition.x,
                                                     &hitPosition.y, &hitPosition.z);
        if (hitType != 0 && hitVolume != 0) {
            if (hitType == 0x10) {
                Obj_StartModelFadeIn(obj, 0x12C);
            } else if ((u32)(hitType - 0xE) <= 1 || hitType == 0x11) {
                Sfx_PlayFromObject(obj, SFXTRIG_mv_ladderslide16);
                hitPosition.x += playerMapOffsetX;
                hitPosition.z += playerMapOffsetZ;
                objDoHitParticleFx(obj, 0.014f, &lightPosition, 1, 0);
                Obj_SetModelColorFadeRecursive(obj, 0xF, 0xC8, 0, 0, 1);
                state->stateIndex = BOMB_PLANT_STATE_EXPLODING;
                state->flags |= BOMB_PLANT_STATE_FLAG_JUST_ENTERED;
                model = obj->anim.modelInstance;
                ObjHitbox_SetCapsuleBounds(&obj->anim, (s16)(model->primaryHitboxRadius + 0x50),
                                           (s16)(model->primaryCapsuleOffsetA - 0x50),
                                           (s16)(model->primaryCapsuleOffsetB + 0x50));
                ObjHits_MarkObjectPositionDirty(&obj->anim);
            }
        }
    }

    if ((config->flags & BOMB_PLANT_CONFIG_ENABLE_HITS) != 0) {
        ObjHits_EnableObject(obj);
    } else {
        ObjHits_DisableObject(obj);
    }

    if ((config->flags & BOMB_PLANT_CONFIG_USE_HIT_VOLUME) != 0) {
        ObjHits_SetHitVolumeSlot(&obj->anim, BOMB_PLANT_HIT_VOLUME_SLOT, 1, 0);
    } else {
        ObjHits_ClearHitVolumes(&obj->anim);
    }

    if ((config->flags & BOMB_PLANT_CONFIG_ENABLE_INTERACT) != 0) {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0 && mainGetBit(GAMEBIT_SawBombPlant) == 0) {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            mainSetBits(GAMEBIT_SawBombPlant, 1);
        }
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }

    if ((config->flags & BOMB_PLANT_CONFIG_HIDDEN) != 0) {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    } else {
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }

    if (obj->anim.currentMove != config->moveId) {
        ObjAnim_SetCurrentMove(obj, config->moveId, 0.0f, 0);
    }

    if (ObjAnim_AdvanceCurrentMove(obj, config->moveStepScale, timeDelta, NULL) != 0) {
        state->flags |= BOMB_PLANT_STATE_FLAG_MOVE_ACTIVE;
    } else {
        state->flags &= ~BOMB_PLANT_STATE_FLAG_MOVE_ACTIVE;
    }
}

void BombPlant_init(GameObject* obj, BombPlantPlacement* placement, int isReload) {
    BombPlantState* state;
    BombPlantPlacement* spawnPlacement;
    s16 gameBit;

    state = obj->extra;
    obj->anim.rotX = (s16)((s32)placement->initialRotX << 8);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->animEventCallback = BombPlant_animEventCallback;
    state->growTargetScale = obj->anim.rootMotionScale;

    if (isReload != 0) {
        return;
    }

    gameBit = placement->gameBit;
    if (gameBit != -1 && mainGetBit(gameBit) == 0) {
        spawnPlacement = (BombPlantPlacement*)obj->anim.placementData;
        obj->anim.alpha = 0xFF;
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        obj->anim.localPosX = spawnPlacement->base.posX;
        obj->anim.localPosY = spawnPlacement->base.posY;
        obj->anim.localPosZ = spawnPlacement->base.posZ;
        obj->anim.rootMotionScale = BOMB_PLANT_MIN_GROW_SCALE;
        state->growDuration = BOMB_PLANT_GROW_DURATION;
        state->growStartScale = state->growTargetScale;
        state->growRate = state->growStartScale / state->growDuration;
        state->growTimer = state->growDuration;
        ObjHits_RefreshObjectState(obj);
        state->stateIndex = BOMB_PLANT_STATE_DORMANT;
    } else {
        spawnPlacement = (BombPlantPlacement*)obj->anim.placementData;
        obj->anim.alpha = 0xFF;
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        obj->anim.localPosX = spawnPlacement->base.posX;
        obj->anim.localPosY = spawnPlacement->base.posY;
        obj->anim.localPosZ = spawnPlacement->base.posZ;
        ObjHits_RefreshObjectState(obj);
    }
}

BombPlantStateConfig gBombPlantStateConfigs[BOMB_PLANT_STATE_CONFIG_COUNT] = {
    {0, 0.005f, BOMB_PLANT_CONFIG_CHECK_HITS | BOMB_PLANT_CONFIG_ENABLE_INTERACT | BOMB_PLANT_CONFIG_ENABLE_HITS},
    {0, 0.0f, BOMB_PLANT_CONFIG_HIDDEN},
    {0, 0.0f, BOMB_PLANT_CONFIG_ENABLE_HITS},
    {2, 0.01f, BOMB_PLANT_CONFIG_CHECK_HITS | BOMB_PLANT_CONFIG_ENABLE_INTERACT | BOMB_PLANT_CONFIG_ENABLE_HITS},
    {1, 0.008f, BOMB_PLANT_CONFIG_ENABLE_HITS | BOMB_PLANT_CONFIG_USE_HIT_VOLUME},
};

ObjectDescriptor10WithPadding gBombPlantObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        0,
        0,
        0,
        (ObjectDescriptorCallback)BombPlant_init,
        (ObjectDescriptorCallback)BombPlant_update,
        (ObjectDescriptorCallback)BombPlant_hitDetect,
        (ObjectDescriptorCallback)BombPlant_render,
        (ObjectDescriptorCallback)BombPlant_free,
        (ObjectDescriptorCallback)BombPlant_getObjectTypeId,
        BombPlant_getExtraSize,
    },
    0,
};
