/*
 * DLL 0xFF - MagicDust.
 *
 * A collectible gem with four effect variants, free-flight and bounce
 * behaviour, proximity effects, and a two-phase collection burst.
 */
#include "dlls/objects/255.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/os/OSReport.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/model.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/dll/player_api.h"
#include "main/gamebits_api.h"
#include "main/obj_link.h"
#include "main/obj_message.h"
#include "sys/objects/lifecycle.h"
#include "dlls/objects/237.h"

#define MAGICGEM_MSG_IN_RANGE    0x7000A /* Sent to the player when a gem enters pickup range. */
#define MAGICGEM_MSG_PICKUP      0x7000B /* Awards magic and starts the collection burst. */
#define MAGICGEM_GAMEBIT_CLAIMED 0x90D   /* Per-frame single-pickup latch. */

#define MAGICGEM_RENDER_SCALE           1.0f
#define MAGICGEM_BURST_TIMER            180.0f
#define MAGICGEM_ACTIVATE_DIST_SQ       250000.0f
#define MAGICGEM_VELOCITY_DAMPING       0.99f
#define MAGICGEM_GRAVITY                0.1f
#define MAGICGEM_ZERO                   0.0f
#define MAGICGEM_LONG_BURST_TIMER       1800.0f
#define MAGICGEM_BOUNCE_SFX_SPEED       0.5f
#define MAGICGEM_FLOOR_NORMAL_THRESHOLD 0.707f
#define MAGICGEM_BOUNCE_RESTITUTION_Y   0.6f
#define MAGICGEM_BOUNCE_RESTITUTION_XZ  0.7f
#define MAGICGEM_PICKUP_Y_RANGE         20.0f
#define MAGICGEM_PICKUP_RADIUS_BASE     8.0f
#define MAGICGEM_RANDOM_SPEED_SCALE     100.0f
#define MAGICGEM_PI                     3.1415927f
#define MAGICGEM_ANGLE_RAND_SCALE       32768.0f
#define MAGICGEM_RANDOM_Y_SPEED_SCALE   50.0f
#define MAGICGEM_FOLLOW_TIME            120.0f
#define MAGICGEM_COLLECT_RADIUS         7.0f
#define MAGICGEM_INITIAL_BURST_TIMER    60.0f

#define MAGICGEM_MIN_ALPHA             1
#define MAGICGEM_MAX_ALPHA             0xFF
#define MAGICGEM_AMBIENT_FX_MODE       0x10002
#define MAGICGEM_BURST_FX_MODE         1
#define MAGICGEM_PARTFX_MODEL_NONE     -1
#define MAGICGEM_BURST_PARTICLE_COUNT  30
#define MAGICGEM_MAX_BOUNCES           5
#define MAGICGEM_PICKUP_PARTICLE_COUNT 0x28
#define MAGICGEM_ROTATION_STEP         0x100

#define MAGICGEM_AMBIENT_TIMER_MIN 0xF0
#define MAGICGEM_AMBIENT_TIMER_MAX 300

#define MAGICGEM_SPAWN_MODE_BURST  1
#define MAGICGEM_SPAWN_MODE_FOLLOW 2
#define MAGICGEM_SPAWN_MODE_DROP   3

#define MAGICGEM_PATH_FLAGS       0x40007
#define MAGICGEM_PATH_POINT_COUNT 1
#define MAGICGEM_MESSAGE_SLOTS    1

#define MAGICGEM_SHADOW_TINT_A 100
#define MAGICGEM_SHADOW_TINT_B 150

#define MAGICGEM_GREEN_TEXTURE_PAIR 0xD10
#define MAGICGEM_RED_TEXTURE_PAIR   0xE11

#define MAGICGEM_GREEN_AMBIENT_EFFECT_ID  0x54F
#define MAGICGEM_GREEN_BURST_EFFECT_ID    0x54B
#define MAGICGEM_GREEN_SFX_ID             0x58
#define MAGICGEM_GREEN_UNK276             0x5B0
#define MAGICGEM_GREEN_PARTICLE_MODE      4
#define MAGICGEM_RED_AMBIENT_EFFECT_ID    0x54E
#define MAGICGEM_RED_BURST_EFFECT_ID      0x54A
#define MAGICGEM_RED_SFX_ID               0x59
#define MAGICGEM_RED_UNK276               0x5B1
#define MAGICGEM_RED_PARTICLE_MODE        1
#define MAGICGEM_YELLOW_TEXTURE_INDEX     3
#define MAGICGEM_YELLOW_AMBIENT_EFFECT_ID 0x54D
#define MAGICGEM_YELLOW_BURST_EFFECT_ID   0x549
#define MAGICGEM_YELLOW_SFX_ID            0x5A
#define MAGICGEM_YELLOW_UNK276            0x5B2
#define MAGICGEM_YELLOW_PARTICLE_MODE     2
#define MAGICGEM_BLUE_TEXTURE_INDEX       2
#define MAGICGEM_BLUE_AMBIENT_EFFECT_ID   0x550
#define MAGICGEM_BLUE_BURST_EFFECT_ID     0x54C
#define MAGICGEM_BLUE_SFX_ID              0x5B
#define MAGICGEM_BLUE_UNK276              0x5B3
#define MAGICGEM_BLUE_PARTICLE_MODE       6

typedef struct MagicGemObjectDef {
    u8 pad00[0xB];  /* 0x00 */
    s8 magicAmount; /* 0x0B */
} MagicGemObjectDef;

STATIC_ASSERT(offsetof(MagicGemObjectDef, magicAmount) == 0xB);

static const u16 sMagicGemGreenTexturePair[2] = {MAGICGEM_GREEN_TEXTURE_PAIR, 0};
static const u16 sMagicGemRedTexturePair[2] = {MAGICGEM_RED_TEXTURE_PAIR, 0};
static u8 sMagicGemPathData[12] = {0};

/* Target data order places the descriptor before the OSReport string. */
ObjectDescriptor gMagicGemObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicDust_init,
    (ObjectDescriptorCallback)MagicDust_update,
    0,
    (ObjectDescriptorCallback)MagicDust_render,
    (ObjectDescriptorCallback)MagicDust_free,
    0,
    MagicDust_getExtraSize,
};

int MagicDust_getExtraSize(void) {
    return sizeof(MagicGemState);
}

void MagicDust_free(GameObject* obj) {
    if (obj->ownerObj != NULL) {
        ObjLink_DetachChild((GameObject*)obj->ownerObj, obj);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void MagicDust_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 unusedVisible) {
    objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, MAGICGEM_RENDER_SCALE);
}

static inline void MagicDust_collect(GameObject* obj, MagicGemState* state, GameObject* player) {
    MagicGemObjectDef* objectDef = (MagicGemObjectDef*)obj->anim.modelInstance->extraSetupData;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    itemPickupDoParticleFx(obj, MAGICGEM_RENDER_SCALE, state->mode, MAGICGEM_PICKUP_PARTICLE_COUNT);
    ObjHits_DisableObject(obj);
    Sfx_PlayFromObject(obj, (u16)state->sfxId);
    Sfx_StopFromObject(obj, SFXTRIG_rfall5_c);
    playerAddRemoveMagic(player, (int)objectDef->magicAmount);
    state->flags &= ~MAGICGEM_FLAG_BURST_MASK;
    state->flags |= MAGICGEM_FLAG_COLLECTED;
    state->flags |= MAGICGEM_FLAG_COLLECT_LATCH;
    state->burstTimer = MAGICGEM_BURST_TIMER;
    OSReport("Magic collected");
    obj->anim.alpha = MAGICGEM_MIN_ALPHA;
}

void MagicDust_update(GameObject* obj) {
    f32 scalar;
    u8 flags;
    GameObject* player;
    int result;
    u32 value;
    MagicGemState* state;
    u8 burstCount;
    char fxVariant;
    int message[1];
    f32 distanceSquared;

    player = Obj_GetPlayerObject();
    state = obj->extra;
    while ((result = ObjMsg_Pop(obj, (u32*)message, NULL, NULL)) != 0) {
        switch (message[0]) {
        case MAGICGEM_MSG_PICKUP:
            MagicDust_collect(obj, state, player);
            break;
        }
    }
    if ((state->flags & MAGICGEM_FLAG_AMBIENT_FX) == 0) {
        if (((state->flags & MAGICGEM_FLAG_COLLECT_LATCH) == 0) &&
            (getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < MAGICGEM_ACTIVATE_DIST_SQ)) {
            state->flags |= MAGICGEM_FLAG_AMBIENT_FX;
            fxVariant = '\0';
            (*gPartfxInterface)
                ->spawnObject((void*)obj, state->ambientEffectId, NULL, MAGICGEM_AMBIENT_FX_MODE,
                              MAGICGEM_PARTFX_MODEL_NONE, &fxVariant);
            fxVariant = '\x01';
            (*gPartfxInterface)
                ->spawnObject((void*)obj, state->ambientEffectId, NULL, MAGICGEM_AMBIENT_FX_MODE,
                              MAGICGEM_PARTFX_MODEL_NONE, &fxVariant);
            fxVariant = '\x02';
            (*gPartfxInterface)
                ->spawnObject((void*)obj, state->ambientEffectId, NULL, MAGICGEM_AMBIENT_FX_MODE,
                              MAGICGEM_PARTFX_MODEL_NONE, &fxVariant);
        }
    } else if (getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) >= MAGICGEM_ACTIVATE_DIST_SQ) {
        state->flags &= ~MAGICGEM_FLAG_AMBIENT_FX;
        (*gExpgfxInterface)->freeSource2((u32)obj);
    }
    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0) {
        if ((state->flags & MAGICGEM_FLAG_SETTLED) != 0) {
            obj->anim.rotX += framesThisStep * MAGICGEM_ROTATION_STEP;
            if ((state->ambientTimer -= framesThisStep) < 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_rfall5_c);
                value = randomGetRange(MAGICGEM_AMBIENT_TIMER_MIN, MAGICGEM_AMBIENT_TIMER_MAX);
                state->ambientTimer = value;
            }
        }
        if (obj->ownerObj != NULL) {
            if (obj->anim.modelState != NULL) {
                obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
            (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
            return;
        }
        if (obj->anim.modelState != NULL) {
            obj->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        state->unk25B = 1;
        if ((state->flags & MAGICGEM_FLAG_MOTION_MASK) == 0) {
            obj->anim.velocityX *= MAGICGEM_VELOCITY_DAMPING;
            obj->anim.velocityZ *= MAGICGEM_VELOCITY_DAMPING;
            obj->anim.velocityY = -(MAGICGEM_GRAVITY * timeDelta - obj->anim.velocityY);
        }
        state->burstTimer -= timeDelta;
        flags = state->flags;
        if ((flags & MAGICGEM_FLAG_BURST1) != 0) {
            if (state->burstTimer <= MAGICGEM_ZERO) {
                state->flags = flags & ~MAGICGEM_FLAG_BURST1;
                state->flags |= MAGICGEM_FLAG_BURST2;
                state->burstTimer = MAGICGEM_LONG_BURST_TIMER;
                obj->anim.alpha = MAGICGEM_MAX_ALPHA;
            }
            if (obj->anim.parent == NULL) {
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, state->burstEffectId, NULL, MAGICGEM_BURST_FX_MODE,
                                  MAGICGEM_PARTFX_MODEL_NONE, NULL);
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, state->burstEffectId, NULL, MAGICGEM_BURST_FX_MODE,
                                  MAGICGEM_PARTFX_MODEL_NONE, NULL);
            }
        } else if ((flags & MAGICGEM_FLAG_BURST2) != 0) {
            if (state->burstTimer <= MAGICGEM_ZERO) {
                state->flags = flags & ~MAGICGEM_FLAG_BURST2;
                state->flags |= MAGICGEM_FLAG_COLLECTED;
                state->burstTimer = MAGICGEM_BURST_TIMER;
                (*gExpgfxInterface)->freeSource2((u32)obj);
                if (obj->anim.parent == NULL) {
                    for (burstCount = MAGICGEM_BURST_PARTICLE_COUNT; burstCount != '\0'; burstCount--) {
                        (*gPartfxInterface)
                            ->spawnObject((void*)obj, state->burstEffectId, NULL, MAGICGEM_BURST_FX_MODE,
                                          MAGICGEM_PARTFX_MODEL_NONE, &burstCount);
                    }
                }
                obj->anim.alpha = MAGICGEM_MIN_ALPHA;
                Sfx_PlayFromObject(obj, SFXTRIG_en_liftstpc);
            }
            objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                    obj->anim.velocityZ * timeDelta);
        } else {
            if (state->burstTimer <= MAGICGEM_ZERO) {
                Obj_FreeObject(obj);
            }
            return;
        }
        if ((state->flags & MAGICGEM_FLAG_MOTION_MASK) == 0) {
            (*gPathControlInterface)->update((void*)obj, (void*)state, timeDelta);
            (*gPathControlInterface)->apply((void*)obj, (void*)state);
            (*gPathControlInterface)->advance((void*)obj, (void*)state, timeDelta);
            if (state->contacted != 0) {
                f32 velocityX = -obj->anim.velocityX;
                f32 velocityY = -obj->anim.velocityY;
                f32 velocityZ = -obj->anim.velocityZ;
                f32 speed = sqrtf(velocityX * velocityX + velocityY * velocityY + velocityZ * velocityZ);
                if (speed > MAGICGEM_BOUNCE_SFX_SPEED) {
                    Sfx_PlayFromObject(obj, SFXTRIG_en_lflsh3_c_16b);
                }
                if (state->contactNormalY >= MAGICGEM_FLOOR_NORMAL_THRESHOLD) {
                    obj->anim.velocityY = -obj->anim.velocityY;
                    obj->anim.velocityY *= MAGICGEM_BOUNCE_RESTITUTION_Y;
                } else {
                    obj->anim.velocityX = -obj->anim.velocityX;
                    obj->anim.velocityZ = -obj->anim.velocityZ;
                    obj->anim.velocityX *= MAGICGEM_BOUNCE_RESTITUTION_XZ;
                    obj->anim.velocityZ *= MAGICGEM_BOUNCE_RESTITUTION_XZ;
                }
                result = state->bounceCount + 1;
                state->bounceCount++;
                if (MAGICGEM_MAX_BOUNCES < (u8)result) {
                    state->flags |= MAGICGEM_FLAG_SETTLED;
                    scalar = MAGICGEM_ZERO;
                    obj->anim.velocityX = MAGICGEM_ZERO;
                    obj->anim.velocityY = scalar;
                    obj->anim.velocityZ = scalar;
                }
            }
        }
    }
    if ((state->flags & MAGICGEM_FLAG_CLAIMED) == 0) {
        switch (state->flags & MAGICGEM_FLAG_COLLECT_LATCH) {
        case 0:
            scalar = obj->anim.localPosY - player->anim.localPosY;
            if (scalar < MAGICGEM_ZERO) {
                scalar = -scalar;
            }
            if (scalar < MAGICGEM_PICKUP_Y_RANGE) {
                distanceSquared = getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX);
                scalar = MAGICGEM_PICKUP_RADIUS_BASE + state->collectRadius;
                if ((distanceSquared < scalar * scalar) && (Obj_IsParentSlackClear(player) != 0)) {
                    value = mainGetBit(MAGICGEM_GAMEBIT_CLAIMED);
                    if (value == 0) {
                        state->pickupMsgArg = -1;
                        ObjMsg_SendToObject(player, MAGICGEM_MSG_IN_RANGE, obj, (u32)&state->pickupMsgArg);
                        ObjHits_DisableObject(obj);
                        mainSetBits(MAGICGEM_GAMEBIT_CLAIMED, 1);
                        state->flags |= MAGICGEM_FLAG_CLAIMED;
                    } else {
                        MagicDust_collect(obj, state, player);
                    }
                }
            }
        }
    }
}

void MagicDust_init(GameObject* obj, CollectibleSetup* placement) {
    s16 mode;
    u32 randomValue;
    GameObject* player;
    ObjModel* model;
    MagicGemState* state;
    f32 angle;
    f32 speed;
    u16 texturePickA[2];
    u16 texturePickB[2];
    u8 pathParams[4];

    state = obj->extra;
    pathParams[0] = 3;
    texturePickA[0] = sMagicGemGreenTexturePair[0];
    texturePickB[0] = sMagicGemRedTexturePair[0];
    randomValue = randomGetRange(0, 0xFFFF);
    speed = (f32)randomGetRange(0x27, 0x2C) / MAGICGEM_RANDOM_SPEED_SCALE;
    angle = (MAGICGEM_PI * (f32)(int)randomValue) / MAGICGEM_ANGLE_RAND_SCALE;
    obj->anim.velocityX = speed * mathSinf(angle);
    obj->anim.velocityZ = speed * mathCosf(angle);
    obj->anim.velocityY = (f32)randomGetRange(0x28, 0x32) / MAGICGEM_RANDOM_Y_SPEED_SCALE;
    mode = placement->spawnMode;
    if (mode == MAGICGEM_SPAWN_MODE_BURST) {
        state->flags |= MAGICGEM_FLAG_BURST1;
        obj->anim.alpha = MAGICGEM_MIN_ALPHA;
    } else if (mode == MAGICGEM_SPAWN_MODE_FOLLOW) {
        state->flags |= MAGICGEM_FLAG_BURST1;
        obj->anim.alpha = MAGICGEM_MIN_ALPHA;
        if (*(u32*)&obj->anim.hitReactState != 0) {
            ObjHits_DisableObject(obj);
        }
        player = Obj_GetPlayerObject();
        obj->anim.velocityX = (player->anim.localPosX - obj->anim.localPosX) / MAGICGEM_FOLLOW_TIME;
        obj->anim.velocityY = (player->anim.localPosY - obj->anim.localPosY) / MAGICGEM_FOLLOW_TIME;
        obj->anim.velocityZ = (player->anim.localPosZ - obj->anim.localPosZ) / MAGICGEM_FOLLOW_TIME;
    } else if (mode == MAGICGEM_SPAWN_MODE_DROP) {
        state->flags |= MAGICGEM_FLAG_BURST1;
        obj->anim.alpha = MAGICGEM_MIN_ALPHA;
        obj->anim.velocityY = -((f32)randomGetRange(0x8C, 0x96) / MAGICGEM_RANDOM_Y_SPEED_SCALE);
    }
    obj->anim.bankIndex = placement->modelIndex;
    if (obj->anim.bankIndex >= obj->anim.modelInstance->modelCount) {
        obj->anim.bankIndex = 0;
    }
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->shadowTintA = MAGICGEM_SHADOW_TINT_A;
        obj->anim.modelState->shadowTintB = MAGICGEM_SHADOW_TINT_B;
    }
    model = Obj_GetActiveModel(obj);
    mode = obj->anim.romDefNo;
    switch (mode) {
    case MAGICGEM_DEF_GREEN:
        randomValue = randomGetRange(0, 1);
        model->textureRefs->swapSelector = *((u8*)texturePickA + randomValue);
        state->ambientEffectId = MAGICGEM_GREEN_AMBIENT_EFFECT_ID;
        state->burstEffectId = MAGICGEM_GREEN_BURST_EFFECT_ID;
        state->sfxId = MAGICGEM_GREEN_SFX_ID;
        state->unk276 = MAGICGEM_GREEN_UNK276;
        state->mode = MAGICGEM_GREEN_PARTICLE_MODE;
        break;
    case MAGICGEM_DEF_RED:
        randomValue = randomGetRange(0, 1);
        model->textureRefs->swapSelector = *((u8*)texturePickB + randomValue);
        state->ambientEffectId = MAGICGEM_RED_AMBIENT_EFFECT_ID;
        state->burstEffectId = MAGICGEM_RED_BURST_EFFECT_ID;
        state->sfxId = MAGICGEM_RED_SFX_ID;
        state->unk276 = MAGICGEM_RED_UNK276;
        state->mode = MAGICGEM_RED_PARTICLE_MODE;
        break;
    case MAGICGEM_DEF_YELLOW:
        model->textureRefs->swapSelector = MAGICGEM_YELLOW_TEXTURE_INDEX;
        state->ambientEffectId = MAGICGEM_YELLOW_AMBIENT_EFFECT_ID;
        state->burstEffectId = MAGICGEM_YELLOW_BURST_EFFECT_ID;
        state->sfxId = MAGICGEM_YELLOW_SFX_ID;
        state->unk276 = MAGICGEM_YELLOW_UNK276;
        state->mode = MAGICGEM_YELLOW_PARTICLE_MODE;
        break;
    case MAGICGEM_DEF_BLUE:
    default:
        model->textureRefs->swapSelector = MAGICGEM_BLUE_TEXTURE_INDEX;
        state->ambientEffectId = MAGICGEM_BLUE_AMBIENT_EFFECT_ID;
        state->burstEffectId = MAGICGEM_BLUE_BURST_EFFECT_ID;
        state->sfxId = MAGICGEM_BLUE_SFX_ID;
        state->unk276 = MAGICGEM_BLUE_UNK276;
        state->mode = MAGICGEM_BLUE_PARTICLE_MODE;
        break;
    }
    state->collectRadius = MAGICGEM_COLLECT_RADIUS;
    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0) {
        (*gPathControlInterface)->init((void*)state, 0, MAGICGEM_PATH_FLAGS, 0);
        (*gPathControlInterface)
            ->setup((void*)state, MAGICGEM_PATH_POINT_COUNT, sMagicGemPathData, &state->collectRadius, pathParams);
        (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    if ((state->flags & MAGICGEM_FLAG_BURST1) != 0) {
        state->burstTimer = MAGICGEM_INITIAL_BURST_TIMER;
    } else {
        state->burstTimer = MAGICGEM_LONG_BURST_TIMER;
        state->flags |= MAGICGEM_FLAG_BURST2;
    }
    ObjMsg_AllocQueue(obj, MAGICGEM_MESSAGE_SLOTS);
}
