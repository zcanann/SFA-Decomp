/*
 * Collectible object family (DLL slot 237 / 0xED).
 *
 * Placement game bits control visibility and persistence. Nearby collectibles
 * either apply their pickup immediately or ask the player object to confirm
 * it. Idle items spin or emit particles; launched items use path-controlled
 * bounce motion until they settle.
 */
#include "dlls/objects/237.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/player_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/obj_hit_region.h"
#include "main/obj_message.h"
#include "main/obj_trigger.h"
#include "main/objanim_update.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/vecmath.h"

#define COLLECTIBLE_SEQ_ID_FIRE_CRYSTAL 0xA8
#define COLLECTIBLE_SEQ_ID_TRUTH_HORN   0x156
#define COLLECTIBLE_SEQ_ID_MOON_SEED    0x6A6
#define COLLECTIBLE_SEQ_ID_NW_FOOD      0x319

#define COLLECTIBLE_PICKUP_CATEGORY_ITEM   1
#define COLLECTIBLE_PICKUP_CATEGORY_HEALTH 4

#define COLLECTIBLE_OBJECT_TYPE_ID   0x13
#define COLLECTIBLE_MODEL_FLAG_COLOR 0x10000

#define COLLECTIBLE_NO_GAME_BIT              -1
#define COLLECTIBLE_HIT_REGION_UNRESOLVED    -2
#define COLLECTIBLE_PICKUP_LATCHED           0x1
#define COLLECTIBLE_BOUNCE_FRAME_COUNT       8
#define COLLECTIBLE_SCATTER_PARTICLE_COUNT   10
#define COLLECTIBLE_INITIAL_DESPAWN_TIME     180.0f
#define COLLECTIBLE_INITIAL_LIFETIME         1800.0f
#define COLLECTIBLE_NW_FOOD_HIDE_FRAME_COUNT 1200

#define COLLECTIBLE_SEQUENCE_EVENT_LAUNCH  1
#define COLLECTIBLE_SEQUENCE_EVENT_MESSAGE 2
#define COLLECTIBLE_SEQUENCE_EVENT_SCATTER 3

#define COLLECTIBLE_MESSAGE_QUEUE_LENGTH  2
#define COLLECTIBLE_DEFAULT_PICKUP_RADIUS 15.0f
#define COLLECTIBLE_PATH_CONFIG           0x40006

static u8 sCollectiblePathData[12] = {0};

typedef struct CollectiblePathWord {
    u8 bytes[4];
} CollectiblePathWord;

static const CollectiblePathWord sCollectiblePathWord = {{0x40, 0x40, 0, 0}};
static const u8 sCollectiblePathByte[1] = {5};

/*
 * The collectible notifies the player when it is in range; the player replies
 * to trigger the pickup.
 */
#define COLLECTIBLE_MSG_IN_RANGE 0x7000A
#define COLLECTIBLE_MSG_PICKUP   0x7000B

#define COLLECTIBLE_PARTFX_SCATTER 0x7EF
#define COLLECTIBLE_PARTFX_IDLE    0x423

void collectible_setPosition(GameObject* obj, f32 x, f32 y, f32 z) {
    CollectibleState* state = (CollectibleState*)obj->extra;

    obj->anim.localPosX = x;
    state->basePosX = x;
    obj->anim.localPosY = y;
    state->basePosY = y;
    obj->anim.localPosZ = z;
    state->basePosZ = z;
    if (mainGetBit(state->hideGameBit) == 0) {
        saveGame_saveObjectPos(obj);
    }
}

void collectible_startBounceMotion(GameObject* obj, f32 velocityX, f32 velocityY, f32 velocityZ) {
    s32 bounceFrames = COLLECTIBLE_BOUNCE_FRAME_COUNT;

    ((CollectibleState*)obj->extra)->bounceTimer = bounceFrames;
    obj->anim.velocityX = velocityX;
    obj->anim.velocityY = velocityY;
    obj->anim.velocityZ = velocityZ;
}

u8 collectible_getVisibilityBitClear(GameObject* obj) {
    return ((CollectibleState*)obj->extra)->visibilityBitClear;
}

void collectible_setVisibilityBitClear(GameObject* obj, u32 clear) {
    ((CollectibleState*)obj->extra)->visibilityBitClear = clear;
}

int collectible_getHitRegionId(GameObject* obj) {
    CollectibleState* state = (CollectibleState*)*(int*)&obj->extra;

    if (state->hitRegionId == COLLECTIBLE_HIT_REGION_UNRESOLVED) {
        f32 worldX = obj->anim.worldPosX;
        f32 worldY = obj->anim.worldPosY;
        f32 worldZ = obj->anim.worldPosZ;
        *(u32*)&state->hitRegionId = (u16)ObjHitRegion_FindContainingId(worldX, worldY, worldZ);
    }
    return state->hitRegionId;
}

void collectible_setDisabled(GameObject* obj, int disabled) {
    CollectibleState* state = (CollectibleState*)obj->extra;

    state->disabled = disabled;
    if (disabled != 0) {
        ObjHits_DisableObject(obj);
    } else if (mainGetBit(state->hideGameBit) == 0) {
        ObjHits_EnableObject(obj);
    }
}

int collectible_getIsHidden(GameObject* obj) {
    return obj->userData1;
}

static f32 collectible_getRotX(GameObject* obj) {
    return (f32)obj->anim.rotX;
}

PPCWGPipe GXWGFifo : (0xCC008000);

void collectible_applyPickup(GameObject* obj) {
    CollectibleState* state = obj->extra;
    CollectibleSetup* setup = *(CollectibleSetup**)&obj->anim.placementData;
    CollectibleModelSetup* modelSetup = (CollectibleModelSetup*)obj->anim.modelInstance->extraSetupData;

    /* Refresh the player and companion lookups before applying pickup effects. */
    Obj_GetPlayerObject();
    getTrickyObject();
    Obj_GetPlayerObject();
    getTrickyObject();
    ObjHits_DisableObject(obj);
    if (obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) {
        state->despawnTimer = COLLECTIBLE_INITIAL_DESPAWN_TIME;
        if (obj->anim.modelState != NULL) {
            obj->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if (state->hideGameBit != COLLECTIBLE_NO_GAME_BIT) {
        mainSetBits(state->hideGameBit, 1);
        saveGame_unsaveObjectPos(obj);
    }
    if (setup->collectGameBit != COLLECTIBLE_NO_GAME_BIT) {
        mainSetBits(setup->collectGameBit, 1);
    }
    if (setup->counterGameBit > 0) {
        gameBitIncrement(setup->counterGameBit);
    }
    switch (modelSetup->pickupCategory) {
    case COLLECTIBLE_PICKUP_CATEGORY_ITEM:
        switch (obj->anim.seqId) {
        case 0x5A:
            Sfx_PlayFromObject((u32)obj, SFXTRIG_lockoff22);
            itemPickupDoParticleFx(obj, 1.0f, 2, 40);
            break;
        case COLLECTIBLE_SEQ_ID_NW_FOOD:
            Sfx_PlayFromObject((u32)obj, SFXTRIG_bapt11_c);
            mainSetBits(GAMEBIT_ITEM_NWFood_Got, 1);
            state->hideFrames = COLLECTIBLE_NW_FOOD_HIDE_FRAME_COUNT;
            itemPickupDoParticleFx(obj, 1.0f, 255, 40);
            break;
        case COLLECTIBLE_SEQ_ID_MOON_SEED: {
            s8 count = mainGetBit(GAMEBIT_ITEM_MoonSeed_Count);
            if (count < 7) {
                count = count + 1;
            }
            mainSetBits(GAMEBIT_ITEM_MoonSeed_Count, count);
            itemPickupDoParticleFx(obj, 1.0f, 6, 40);
            Sfx_PlayFromObject((u32)obj, SFXTRIG_lockoff22);
            break;
        }
        case 0x22:
            Sfx_PlayFromObject((u32)obj, SFXTRIG_lockoff22);
            itemPickupDoParticleFx(obj, 1.0f, 255, 40);
            break;
        default:
            Sfx_PlayFromObject((u32)obj, SFXTRIG_cam90_c);
            itemPickupDoParticleFx(obj, 1.0f, 255, 40);
            break;
        }
        break;
    case COLLECTIBLE_PICKUP_CATEGORY_HEALTH:
        switch (obj->anim.seqId) {
        case COLLECTIBLE_ITEM_ENERGY_EGG:
            Sfx_PlayFromObject((u32)Obj_GetPlayerObject(), SFXTRIG_lockoff22);
            playerAddHealth(Obj_GetPlayerObject(), 4);
            itemPickupDoParticleFx(obj, 1.0f, 3, 40);
            break;
        case COLLECTIBLE_ITEM_APPLE:
            playerAddHealth(Obj_GetPlayerObject(), 2);
            Sfx_PlayFromObject((u32)Obj_GetPlayerObject(), SFXTRIG_lockoff22);
            itemPickupDoParticleFx(obj, 1.0f, 1, 40);
            break;
        default:
            Sfx_PlayFromObject((u32)Obj_GetPlayerObject(), SFXTRIG_cam90_c);
            itemPickupDoParticleFx(obj, 1.0f, 255, 40);
            break;
        }
        break;
    default:
        Sfx_PlayFromObject((u32)obj, SFXTRIG_cam90_c);
        itemPickupDoParticleFx(obj, 1.0f, 255, 40);
        break;
    }
    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase;
    obj->userData1 = 1;
}

static void collectible_updateSeqEffects(GameObject* obj) {
    switch (obj->anim.seqId) {
    case COLLECTIBLE_SEQ_ID_MOON_SEED:
        objfx_spawnDirectionalBurst(obj, 5, 1.0f, 6, 1, 0x14, 3.0f, NULL, 0);
        break;
    }
}

void collectible_updateLooseMotion(GameObject* obj) {
    u8* state = obj->extra;
    if (obj->anim.seqId == COLLECTIBLE_SEQ_ID_MOON_SEED) {
        objMove(obj, 0.0f, obj->anim.velocityY * framesThisStep, 0.0f);
    } else {
        u32 frameCount = framesThisStep;
        objMove(obj, obj->anim.velocityX * frameCount, obj->anim.velocityY * frameCount,
                obj->anim.velocityZ * frameCount);
    }
    (*gPathControlInterface)->update(obj, state + offsetof(CollectibleState, pathState), timeDelta);
    (*gPathControlInterface)->apply(obj, state + offsetof(CollectibleState, pathState));
    (*gPathControlInterface)->advance(obj, state + offsetof(CollectibleState, pathState), timeDelta);
    if (((CollectibleState*)state)->bounceHitFlag != 0) {
        f32 inverseVelocityX = -obj->anim.velocityX;
        f32 inverseVelocityY = -obj->anim.velocityY;
        f32 inverseVelocityZ = -obj->anim.velocityZ;
        f32 speed = sqrtf(inverseVelocityX * inverseVelocityX + inverseVelocityY * inverseVelocityY +
                          inverseVelocityZ * inverseVelocityZ);
        if (0.0f != speed) {
            f32 inverseSpeed = 1.0f / speed;
            inverseVelocityX = inverseVelocityX * inverseSpeed;
            inverseVelocityY = inverseVelocityY * inverseSpeed;
            inverseVelocityZ = inverseVelocityZ * inverseSpeed;
        }
        {
            f32 normalX = *(f32*)(state + offsetof(CollectibleState, bounceNormalX));
            f32 normalY = *(f32*)(state + offsetof(CollectibleState, bounceNormalY));
            f32 normalZ = *(f32*)(state + offsetof(CollectibleState, bounceNormalZ));
            f32 projectionScale =
                2.0f * (inverseVelocityX * normalX + inverseVelocityY * normalY + inverseVelocityZ * normalZ);
            obj->anim.velocityX = normalX * projectionScale;
            obj->anim.velocityY = normalY * projectionScale;
            obj->anim.velocityZ = normalZ * projectionScale;
        }
        obj->anim.velocityX -= inverseVelocityX;
        obj->anim.velocityY -= inverseVelocityY;
        obj->anim.velocityZ -= inverseVelocityZ;
        obj->anim.velocityY *= speed;
        obj->anim.velocityY *= 0.85f;
        obj->anim.velocityX *= speed;
        obj->anim.velocityZ *= speed;
        ((CollectibleState*)state)->bounceTimer -= 1;
        if (((CollectibleState*)state)->bounceTimer == 0) {
            f32 z;
            ((CollectibleState*)state)->bounceTimer = 0;
            z = 0.0f;
            obj->anim.velocityX = z;
            obj->anim.velocityY = z;
            obj->anim.velocityZ = z;
        }
    } else {
        f32 airFriction = 0.99f;
        obj->anim.velocityY = obj->anim.velocityY * airFriction;
        obj->anim.velocityY = -(0.07f * timeDelta - obj->anim.velocityY);
    }
}

void collectible_updateIdleMotion(GameObject* obj) {
    u8* state = obj->extra;

    switch (obj->anim.seqId) {
    case COLLECTIBLE_ITEM_ENERGY_EGG:
        if ((((CollectibleState*)state)->spinTimer -= framesThisStep) <= 0) {
            ((CollectibleState*)state)->spinSpeed = (f32)(s32)randomGetRange(600, 800);
            ((CollectibleState*)state)->spinTimer = randomGetRange(180, 240);
            Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_169);
        }
        obj->anim.rotY = ((CollectibleState*)state)->spinSpeed;
        ((CollectibleState*)state)->spinSpeed *= -0.8f;
        if (obj->anim.rotY < 10 && obj->anim.rotY > -10) {
            obj->anim.rotY = 0;
        }
        break;
    case 0x12d:
    case 0x135:
    case 0x137:
    case COLLECTIBLE_SEQ_ID_TRUTH_HORN:
    case 0x246:
        obj->anim.rotX = 200.0f * timeDelta + (f32)obj->anim.rotX;
        break;
    case 0x22:
        obj->anim.rotX = 200.0f * timeDelta + (f32)obj->anim.rotX;
        itemPickupDoParticleFx(obj, 1.0f, 10, 1);
        break;
    case 0x27f:
        if (*(f32*)(state + offsetof(CollectibleState, playerDistance)) < 200.0f) {
            if ((int)randomGetRange(0, 10) == 0) {
                (*gPartfxInterface)->spawnObject((void*)obj, COLLECTIBLE_PARTFX_IDLE, NULL, 2, -1, NULL);
            }
            obj->anim.rotX += (s16)(182.0f * timeDelta);
        }
        break;
    case 0x5e8:
        obj->anim.rotX = 200.0f * timeDelta + (f32)obj->anim.rotX;
        itemPickupDoParticleFx(obj, 1.0f, 9, 1);
        break;
    }
}

int collectible_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate) {
    CollectibleState* state = obj->extra;
    PartFxSpawnParams spawn;
    int particleIndex;
    int eventIndex;
    f32 velocityZ;
    f32 velocityX;
    f32 velocityY;

    (void)unused;

    if (((CollectibleState*)state)->visibilityGameBit != COLLECTIBLE_NO_GAME_BIT) {
        ((CollectibleState*)state)->visibilityBitClear =
            (u8)(mainGetBit((s32)((CollectibleState*)state)->visibilityGameBit) == 0);
    }
    if (((CollectibleState*)state)->visibilityBitClear == 0) {
        switch (obj->anim.seqId) {
        case COLLECTIBLE_SEQ_ID_MOON_SEED:
            objfx_spawnDirectionalBurst(obj, 5, 1.0f, 6, 1, 0x14, 3.0f, NULL, 0);
            break;
        }
    }

    animUpdate->sequenceEventActive = 0;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        u8 eventId = animUpdate->eventIds[eventIndex];
        if (eventId == COLLECTIBLE_SEQUENCE_EVENT_LAUNCH) {
            velocityZ = 8.0f * mathCosf(2.5770879f);
            velocityX = 8.0f * mathSinf(2.5770879f);
            ((CollectibleState*)obj->extra)->bounceTimer = COLLECTIBLE_BOUNCE_FRAME_COUNT;
            obj->anim.velocityX = velocityX;
            obj->anim.velocityY = (velocityY = 2.0f);
            obj->anim.velocityZ = velocityZ;
            ((CollectibleState*)obj->extra)->bounceTimer = COLLECTIBLE_BOUNCE_FRAME_COUNT;
            obj->anim.velocityX = 4.0f;
            obj->anim.velocityY = velocityY;
            obj->anim.velocityZ = 0.0f;
        } else if (eventId == COLLECTIBLE_SEQUENCE_EVENT_MESSAGE) {
            ((CollectibleState*)state)->delayedMsgTimer = 1;
        } else if (eventId == COLLECTIBLE_SEQUENCE_EVENT_SCATTER) {
            f32 z;
            particleIndex = 0;
            z = 0.0f;
            for (; particleIndex < COLLECTIBLE_SCATTER_PARTICLE_COUNT; particleIndex++) {
                spawn.posX = z;
                spawn.posY = z;
                spawn.posZ = z;
                (*gPartfxInterface)->spawnObject((void*)obj, COLLECTIBLE_PARTFX_SCATTER, &spawn, 1, -1, NULL);
            }
        }
    }
    return 0;
}

void collectible_checkProximityPickup(GameObject* obj, u8* state) {
    GameObject* player;
    CollectibleSetup* placement;
    GameObject* focus;
    f32 distance;
    f32 verticalDistance;

    placement = (CollectibleSetup*)obj->anim.placementData;
    player = Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }
    if ((state[offsetof(CollectibleState, pickupLatch)] & COLLECTIBLE_PICKUP_LATCHED) != 0) {
        return;
    }
    focus = playerGetFocusObject(player);
    if (focus == NULL) {
        focus = player;
    }
    distance = Vec_xzDistance(&obj->anim.worldPosX, &focus->anim.worldPosX);
    verticalDistance = focus->anim.worldPosY - obj->anim.worldPosY;
    if (verticalDistance < 0.0f) {
        verticalDistance = -verticalDistance;
    }
    if (verticalDistance < 100.0f && distance < ((CollectibleState*)state)->pickupRadius &&
        Obj_IsParentSlackClear(player) != 0) {
        ((CollectibleState*)state)->pickupMsgValue = -1;
        switch (obj->anim.seqId) {
        case COLLECTIBLE_ITEM_ENERGY_EGG:
            if (mainGetBit(GAMEBIT_SawBigHealth) == 0) {
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, (void*)obj,
                                    (u32)(state + offsetof(CollectibleState, pickupMsgValue)));
                mainSetBits(GAMEBIT_SawBigHealth, 1);
            } else {
                collectible_applyPickup(obj);
            }
            state[offsetof(CollectibleState, pickupLatch)] |= COLLECTIBLE_PICKUP_LATCHED;
            break;
        case COLLECTIBLE_SEQ_ID_NW_FOOD:
            collectible_applyPickup(obj);
            state[offsetof(CollectibleState, pickupLatch)] |= COLLECTIBLE_PICKUP_LATCHED;
            break;
        case 0x49:
        case 0x2da:
        case COLLECTIBLE_ITEM_APPLE:
            if (mainGetBit(GAMEBIT_SawApple) == 0) {
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, (void*)obj,
                                    (u32)(state + offsetof(CollectibleState, pickupMsgValue)));
                mainSetBits(GAMEBIT_SawApple, 1);
            } else {
                collectible_applyPickup(obj);
            }
            state[offsetof(CollectibleState, pickupLatch)] |= COLLECTIBLE_PICKUP_LATCHED;
            break;
        case COLLECTIBLE_SEQ_ID_MOON_SEED:
            if (mainGetBit(GAMEBIT_CollectedFlag09A8) == 0) {
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, (void*)obj,
                                    (u32)(state + offsetof(CollectibleState, pickupMsgValue)));
                mainSetBits(GAMEBIT_CollectedFlag09A8, 1);
            } else {
                collectible_applyPickup(obj);
            }
            state[offsetof(CollectibleState, pickupLatch)] |= COLLECTIBLE_PICKUP_LATCHED;
            break;
        default:
            if (ObjTrigger_IsSet((int)obj) != 0) {
                mainSetBits(GAMEBIT_EnableCMenu, 1);
                ((CollectibleState*)state)->pickupMsgValue = placement->collectGameBit;
                ObjMsg_SendToObject(player, COLLECTIBLE_MSG_IN_RANGE, (void*)obj,
                                    (u32)(state + offsetof(CollectibleState, pickupMsgValue)));
                state[offsetof(CollectibleState, pickupLatch)] |= COLLECTIBLE_PICKUP_LATCHED;
                if (obj->anim.modelState != NULL) {
                    obj->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
            }
            break;
        }
    }
    *(f32*)(state + offsetof(CollectibleState, playerDistance)) = distance;
}

int collectible_getExtraSize(void) {
    return sizeof(CollectibleState);
}

int collectible_getObjectTypeId(void) {
    return COLLECTIBLE_OBJECT_TYPE_ID;
}

void collectible_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
    ObjGroup_RemoveObject((int)obj, COLLECTIBLE_OBJECT_GROUP);
}

void collectible_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    CollectibleState* state = *(CollectibleState**)&obj->extra;
    f32 zero = 0.0f;

    if (visible != 0 && ((CollectibleState*)state)->despawnTimer == zero && obj->userData1 == 0 &&
        (obj->anim.seqId == COLLECTIBLE_SEQ_ID_TRUTH_HORN || ((CollectibleState*)state)->visibilityBitClear == 0)) {
        if ((obj->anim.modelInstance->flags & COLLECTIBLE_MODEL_FLAG_COLOR) != 0 &&
            ((CollectibleState*)state)->useColor != 0) {
            objSetColorFilter(((CollectibleState*)state)->colorR, ((CollectibleState*)state)->colorG,
                        ((CollectibleState*)state)->colorB);
        }
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
        if (obj->anim.seqId == COLLECTIBLE_SEQ_ID_FIRE_CRYSTAL) {
            objfx_spawnDirectionalBurst(obj, 7, 1.0f, 5, 1, 10, 4.0f, NULL, 0x20000000);
        }
    }
}

void collectible_hitDetect(GameObject* obj) {
    (void)obj;
}

void collectible_update(GameObject* obj) {
    u8* state = obj->extra;
    ObjHitsPriorityState* hitState;
    int messageParam;
    int messageId;
    int hideFrames;
    f32 timer;
    f32 zero;

    *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    timer = ((CollectibleState*)state)->despawnTimer;
    zero = 0.0f;
    if (timer != zero) {
        ((CollectibleState*)state)->despawnTimer = timer - timeDelta;
        if (((CollectibleState*)state)->despawnTimer <= zero) {
            ((CollectibleState*)state)->despawnTimer = zero;
            ObjHits_DisableObject(obj);
            if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0) {
                Obj_FreeObject(obj);
            }
        }
        return;
    }
    if (((CollectibleState*)state)->visibilityGameBit != COLLECTIBLE_NO_GAME_BIT) {
        ((CollectibleState*)state)->visibilityBitClear =
            (u8)(mainGetBit((s32)((CollectibleState*)state)->visibilityGameBit) == 0);
    }
    if (((CollectibleState*)state)->visibilityBitClear != 0 || state[offsetof(CollectibleState, disabled)] != 0) {
        return;
    }
    switch (obj->anim.seqId) {
    case COLLECTIBLE_SEQ_ID_MOON_SEED:
        objfx_spawnDirectionalBurst(obj, 5, 1.0f, 6, 1, 0x14, 3.0f, NULL, 0);
        break;
    }
    timer = ((CollectibleState*)state)->lifetimeTimer;
    zero = 0.0f;
    if (timer != zero) {
        ((CollectibleState*)state)->lifetimeTimer = timer - timeDelta;
        if (((CollectibleState*)state)->lifetimeTimer <= zero) {
            if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0) {
                ((CollectibleState*)state)->despawnTimer = COLLECTIBLE_INITIAL_DESPAWN_TIME;
                if (obj->anim.modelState != NULL) {
                    obj->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
                itemPickupDoParticleFx(obj, 1.0f, 255, 40);
            }
            ((CollectibleState*)state)->lifetimeTimer = 0.0f;
            return;
        }
    }
    while (ObjMsg_Pop((void*)obj, (u32*)&messageId, (u32*)&messageParam, NULL) != 0) {
        switch (messageId) {
        case COLLECTIBLE_MSG_PICKUP:
            collectible_applyPickup(obj);
            break;
        }
    }
    switch (obj->anim.seqId) {
    case COLLECTIBLE_SEQ_ID_NW_FOOD:
        hideFrames = ((CollectibleState*)state)->hideFrames;
        if (hideFrames != 0) {
            ((CollectibleState*)state)->hideFrames -= framesThisStep;
            if (((CollectibleState*)state)->hideFrames <= 0) {
                ((CollectibleState*)state)->hideFrames = 0;
                state[offsetof(CollectibleState, pickupLatch)] &= ~COLLECTIBLE_PICKUP_LATCHED;
                obj->anim.alpha = 255;
                obj->userData1 = 0;
            }
        }
        break;
    }
    if (obj->userData1 != 0) {
        if (obj->anim.hitReactState != NULL) {
            hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            hitState->flags |= OBJHITS_PRIORITY_STATE_HIT_EXCLUDED;
        }
        ObjHits_DisableObject(obj);
        if (((CollectibleState*)state)->hideGameBit != COLLECTIBLE_NO_GAME_BIT &&
            mainGetBit((s32)((CollectibleState*)state)->hideGameBit) == 0) {
            obj->userData1 = 0;
        }
    } else {
        *(u8*)&obj->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        collectible_updateIdleMotion(obj);
        if (((CollectibleState*)state)->bounceTimer != 0) {
            collectible_updateLooseMotion(obj);
        }
        if (state[offsetof(CollectibleState, delayedMsgTimer)] != 0) {
            state[offsetof(CollectibleState, delayedMsgTimer)]--;
            if (state[offsetof(CollectibleState, delayedMsgTimer)] == 0) {
                ((CollectibleState*)state)->pickupMsgValue = -1;
                ObjMsg_SendToObject(Obj_GetPlayerObject(), COLLECTIBLE_MSG_IN_RANGE, (void*)obj,
                                    (u32)(state + offsetof(CollectibleState, pickupMsgValue)));
            }
        } else {
            collectible_checkProximityPickup(obj, state);
        }
    }
}

void collectible_init(GameObject* obj, CollectibleSetup* setup) {
    ObjAnimComponent* objAnim;
    u8* state = obj->extra;
    int modelIndex;
    u8* modelData;
    CollectiblePathWord pathSetup = sCollectiblePathWord;
    u8 pathControlByte;

    objAnim = &obj->anim;
    pathControlByte = sCollectiblePathByte[0];
    ObjGroup_AddObject((int)obj, COLLECTIBLE_OBJECT_GROUP);
    ObjMsg_AllocQueue(obj, COLLECTIBLE_MESSAGE_QUEUE_LENGTH);
    obj->anim.rotX = (s16)(setup->rotXByte << 8);
    obj->anim.rotY = (s16)(setup->rotYByte << 8);
    obj->anim.rotZ = (s16)(setup->rotZByte << 8);
    obj->anim.rootMotionScale = objAnim->modelInstance->rootMotionScaleBase;
    obj->animEventCallback = collectible_SeqFn;
    modelIndex = setup->modelIndex;
    objAnim->bankIndex = modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = 0;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    ((CollectibleState*)state)->unk0C = setup->unk19;
    ((CollectibleState*)state)->unk0D = setup->unk1A;
    ((CollectibleState*)state)->disabled = 0;
    ((CollectibleState*)state)->hitRegionId = COLLECTIBLE_HIT_REGION_UNRESOLVED;
    ((CollectibleState*)state)->bounceTimer = 0;
    ((CollectibleState*)state)->visibilityGameBit = setup->visibilityGameBit;
    ((CollectibleState*)state)->mapId = setup->base.mapId;
    ((CollectibleState*)state)->basePosX = obj->anim.localPosX;
    ((CollectibleState*)state)->basePosY = obj->anim.localPosY;
    ((CollectibleState*)state)->basePosZ = obj->anim.localPosZ;
    ((CollectibleState*)state)->useColor = setup->useColor;
    ((CollectibleState*)state)->delayedMsgTimer = 0;
    if (((CollectibleState*)state)->visibilityGameBit != COLLECTIBLE_NO_GAME_BIT) {
        ((CollectibleState*)state)->visibilityBitClear =
            (u8)((u32)__cntlzw(mainGetBit(((CollectibleState*)state)->visibilityGameBit)) >> 5);
    }
    ((CollectibleState*)state)->hideGameBit = setup->hideGameBit;
    if (((CollectibleState*)state)->hideGameBit != COLLECTIBLE_NO_GAME_BIT) {
        *(u32*)&obj->userData1 = mainGetBit(((CollectibleState*)state)->hideGameBit);
    } else {
        *(u32*)&obj->userData1 = 0;
    }
    if (obj->userData1 == 0) {
        modelData = obj->anim.modelInstance->extraSetupData;
        if (modelData != NULL) {
            ((CollectibleState*)state)->pickupRadius = (f32)((CollectibleModelSetup*)modelData)->pickupRadius;
        } else {
            ((CollectibleState*)state)->pickupRadius = COLLECTIBLE_DEFAULT_PICKUP_RADIUS;
        }
        modelData = (u8*)obj->anim.modelInstance->hitVolumes;
        if (modelData != NULL) {
            ((CollectibleState*)state)->pickupRadius = (f32)(((ObjDefHitVolume*)modelData)->bounds[0] << 2);
        }
        if ((obj->anim.modelInstance->flags & COLLECTIBLE_MODEL_FLAG_COLOR) != 0 &&
            ((CollectibleState*)state)->useColor != 0) {
            ((CollectibleState*)state)->colorR = setup->colorR;
            ((CollectibleState*)state)->colorG = setup->colorG;
            ((CollectibleState*)state)->colorB = setup->colorB;
        }
        switch (obj->anim.seqId) {
        case COLLECTIBLE_ITEM_ENERGY_EGG:
            ((CollectibleState*)state)->unk40 = 0.0f;
            ((CollectibleState*)state)->lifetimeTimer = COLLECTIBLE_INITIAL_LIFETIME;
            break;
        case COLLECTIBLE_ITEM_APPLE:
            ((CollectibleState*)state)->unk40 = 3.2f;
            ((CollectibleState*)state)->lifetimeTimer = COLLECTIBLE_INITIAL_LIFETIME;
            break;
        default:
            ((CollectibleState*)state)->unk40 = 10.0f;
            break;
        }
        (*gPathControlInterface)->init(state + offsetof(CollectibleState, pathState), 0, COLLECTIBLE_PATH_CONFIG, 1);
        (*gPathControlInterface)
            ->setup(state + offsetof(CollectibleState, pathState), 1, sCollectiblePathData, pathSetup.bytes,
                    &pathControlByte);
        (*gPathControlInterface)->attachObject((void*)obj, state + offsetof(CollectibleState, pathState));
    }
}

void collectible_release(void) {
}

void collectible_initialise(void) {
}

ObjectDescriptor17 gCollectibleObjDescriptor = {
    0,                                                           /* reserved0 */
    0,                                                           /* reserved1 */
    0,                                                           /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_17_SLOTS,                            /* slotCountAndFlags */
    (ObjectDescriptorCallback)collectible_initialise,            /* initialise */
    (ObjectDescriptorCallback)collectible_release,               /* release */
    0,                                                           /* slot02 */
    (ObjectDescriptorCallback)collectible_init,                  /* init */
    (ObjectDescriptorCallback)collectible_update,                /* update */
    (ObjectDescriptorCallback)collectible_hitDetect,             /* hitDetect */
    (ObjectDescriptorCallback)collectible_render,                /* render */
    (ObjectDescriptorCallback)collectible_free,                  /* free */
    (ObjectDescriptorCallback)collectible_getObjectTypeId,       /* getObjectTypeId */
    collectible_getExtraSize,                                    /* getExtraSize */
    (ObjectDescriptorCallback)collectible_getIsHidden,           /* slot0A */
    (ObjectDescriptorCallback)collectible_setDisabled,           /* slot0B */
    (ObjectDescriptorCallback)collectible_getHitRegionId,        /* slot0C */
    (ObjectDescriptorCallback)collectible_startBounceMotion,     /* slot0D */
    (ObjectDescriptorCallback)collectible_setVisibilityBitClear, /* slot0E */
    (ObjectDescriptorCallback)collectible_getVisibilityBitClear, /* slot0F */
    (ObjectDescriptorCallback)collectible_setPosition,           /* slot10 */
};
