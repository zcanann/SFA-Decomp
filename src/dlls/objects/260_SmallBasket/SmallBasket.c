/*
 * DLL 0x104 - SmallBasket.
 *
 * A carryable, throwable container with collision-driven contents, optional
 * respawning, and a disguise-gated chain-hit variant.
 */
#include "dlls/objects/260_SmallBasket.h"
#include "dlls/objects/237.h"
#include "dlls/objects/262.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/pad.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/player_api.h"
#include "main/dll/player_state.h"
#include "main/dll/player_status.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEvent.h"
#include "main/object_render.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/obj_trigger.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/pad.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "main/sky_interface.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

const f32 gSmallBasketPercentScale[1] = {100.0f};
const f32 gSmallBasketEffectScale[1] = {0.014f};
const f32 gSmallBasketZero[1] = {0.0f};
const f32 gSmallBasketQuarter[1] = {0.25f};
const f32 gSmallBasketHealthPercentLow[1] = {50.0f};
const f32 gSmallBasketHealthPercentHigh[1] = {75.0f};
const f32 gSmallBasketBurstVelocityXZ[1] = {3.0f};
const f32 gSmallBasketBurstVelocityY[1] = {4.0f};
const f32 gSmallBasketOne[1] = {1.0f};
const f32 gSmallBasketVelocityStep[1] = {0.01f};
const f32 gSmallBasketThrowVelocityY[1] = {2.2f};

#define SMALLBASKET_HIT_VOLUME_SLOT 0xE

#define SMALLBASKET_OBJECT_GROUP    0x10
#define SMALLBASKET_MSG_PLAYER_GRAB 0x100010
#define SMALLBASKET_RESOURCE_ID     0x5B
#define SMALLBASKET_RESOURCE_COUNT  1

#define SMALLBASKET_HIT_DISABLE_FRAMES    0x32
#define SMALLBASKET_RETURN_DISABLE_FRAMES 500
#define SMALLBASKET_FLIGHT_FRAMES         800
#define SMALLBASKET_MODEL_FADE_FRAMES     300
#define SMALLBASKET_FADE_STEP             8.0f
#define SMALLBASKET_ALPHA_MAX             0xFF

#define SMALLBASKET_RESPAWN_MIN_DISTANCE gSmallBasketPercentScale[0]
#define SMALLBASKET_DEFAULT_LEASH_RANGE  0x14
#define SMALLBASKET_FRAMES_PER_MINUTE    0x3C
#define SMALLBASKET_RANDOM_DELAY_MAX     100
#define SMALLBASKET_RANDOM_DELAY_BASE    300

#define SMALLBASKET_YAW_HALF_TURN 0x8000
#define SMALLBASKET_YAW_WRAP      0xFFFF
#define SMALLBASKET_TRACK_MASK    0xFF

#define SMALLBASKET_HIT_SFX_VARIANT_A      0x60
#define SMALLBASKET_HIT_SFX_DISGUISE_GATED 0x37D
#define SMALLBASKET_HIT_SFX_DEFAULT        0x4A

/* Remaining retail OBJECTS.bin child names; Scarab IDs live in their canonical header. */
#define SMALLBASKET_CHILD_OBJECT_ENERGY_EGG COLLECTIBLE_ITEM_ENERGY_EGG
#define SMALLBASKET_CHILD_OBJECT_APPLE      COLLECTIBLE_ITEM_APPLE

typedef void (*SmallBasketBreakEffectFn)(GameObject* obj, int arg1, int arg2, int arg3, int arg4, int arg5);

/* Known fields shared by the 0x24- and 0x30-byte child placement records. */
typedef struct SmallBasketCollisionResults {
    f32 hitInfo[4][4]; /* 0x00 */
    f32 radii[4];      /* 0x40 */
    s8 hitAxes[12];    /* 0x50 */
    u32 solidFlags[4]; /* 0x5C */
} SmallBasketCollisionResults;

typedef struct SmallBasketResource {
    void* pad00;
    SmallBasketBreakEffectFn spawnBreakEffect; /* 0x04 */
} SmallBasketResource;


STATIC_ASSERT(offsetof(SmallBasketCollisionResults, hitInfo) == 0x0);
STATIC_ASSERT(offsetof(SmallBasketCollisionResults, radii) == 0x40);
STATIC_ASSERT(offsetof(SmallBasketCollisionResults, hitAxes) == 0x50);
STATIC_ASSERT(offsetof(SmallBasketCollisionResults, solidFlags) == 0x5C);
STATIC_ASSERT(sizeof(SmallBasketCollisionResults) == 0x6C);

STATIC_ASSERT(offsetof(SmallBasketResource, pad00) == 0x0);
STATIC_ASSERT(offsetof(SmallBasketResource, spawnBreakEffect) == 0x4);
STATIC_ASSERT(sizeof(SmallBasketResource) == 0x8);

int gSmallBasketDisableOnHit = 1;
f32 gSmallBasketChainHitRadius = 15.0f;
f32 gSmallBasketChainHitHeight = 30.0f;
f32 gSmallBasketHitVelocity[4];
SmallBasketResource** gSmallBasketResource;

/* Handles SmallBasket hit effects, nearby-object damage, and content drops. */
void SmallBasket_handleHit(GameObject* obj, GameObject* player, SmallBasketState* state) {
    int hitScratch[4];
    PartFxSpawnParams effectParams;
    int hitType;
    int* objectCursor;
    int objectIndex;
    int* objectGroup;
    f32 sourceY;
    f32 candidateY;
    f32 zero;

    hitType = ObjHits_GetPriorityHitWithPosition(obj, &hitScratch[3], &hitScratch[2], (u32*)&hitScratch[1],
                                                 &effectParams.posX, &effectParams.posY, &effectParams.posZ);
    if (hitType != 0) {
        if (hitType == 0x10) {
            Obj_StartModelFadeIn(obj, SMALLBASKET_MODEL_FADE_FRAMES);
        } else {
            effectParams.posX += playerMapOffsetX;
            effectParams.posZ += playerMapOffsetZ;
            if (state->disguiseGated != 0) {
                if (hitType != 5) {
                    objLightFn_8009a1dc((void*)obj, gSmallBasketEffectScale[0], &effectParams, 4, 0);
                    if (Sfx_IsPlayingFromObject(0, SFXTRIG_staff_rocket_powerup) == 0) {
                        Sfx_PlayFromObject((u32)obj, SFXTRIG_staff_rocket_powerup);
                    }
                    return;
                }
                objectGroup = (int*)ObjGroup_GetObjects(SMALLBASKET_OBJECT_GROUP, &hitScratch[0]);
                objectIndex = 0;
                objectCursor = objectGroup;
                for (; objectIndex < hitScratch[0]; objectIndex++) {
                    if (ObjHits_IsObjectEnabled((ObjAnimComponent*)*objectCursor) != 0) {
                        candidateY = ((GameObject*)*objectCursor)->anim.localPosY;
                        sourceY = obj->anim.localPosY;
                        if (candidateY > sourceY && candidateY < sourceY + gSmallBasketChainHitHeight) {
                            if (Vec_xzDistance((f32*)(*objectCursor + 0x18), &obj->anim.worldPosX) <
                                gSmallBasketChainHitRadius) {
                                ObjHits_RecordObjectHit((GameObject*)*objectCursor, (GameObject*)hitScratch[3], 5, 1,
                                                        0);
                            }
                        }
                    }
                    objectCursor++;
                }
            }
            objLightFn_8009a1dc((void*)obj, gSmallBasketEffectScale[0], &effectParams, 1, 0);
            Obj_SetModelColorFadeRecursive(obj, 0xF, 0xC8, 0, 0, 1);
            if (Sfx_IsPlayingFromObject(0, (u16)state->hitSfxId) == 0) {
                Sfx_PlayFromObject((u32)obj, (u16)state->hitSfxId);
            }
            state->disableTimer = SMALLBASKET_HIT_DISABLE_FRAMES;
            state->throwState = SMALLBASKET_THROW_NONE;
            SmallBasket_spawnContents(obj, player, state);
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            zero = gSmallBasketZero[0];
            obj->anim.velocityX = gSmallBasketZero[0];
            obj->anim.velocityZ = zero;
            ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
            if (gSmallBasketDisableOnHit != 0) {
                ObjHits_DisableObject(obj);
            }
        }
    }
}

int SmallBasket_spawnContents(GameObject* obj, GameObject* player, SmallBasketState* state) {
    GameObject* playerRef;
    s16 subtypeChoice;
    f32* collisionVelocity;
    f32* hitVelocity;
    u8 useHitVelocity;
    int selectedSubtype;
    u8* childPlacement;
    u8* child;
    int enableGameBit;
    int maxCount;
    int heading;
    int angleDelta;
    f32 healthPercent;
    f32 health;
    f32 maxHealth;
    f32 burstScale;
    f32 horizontalMagnitude;
    PartFxSpawnParams rotation;

    playerRef = player;
    useHitVelocity = 0;
    enableGameBit = state->enableGameBit;
    if (enableGameBit != -1) {
        mainSetBits(enableGameBit, 1);
    }
    if (Obj_IsLoadingLocked() == 0) {
        return 0;
    }
    hitVelocity = gSmallBasketHitVelocity;
    if (hitVelocity[1] < gSmallBasketQuarter[0]) {
        useHitVelocity = 1;
    }
    if (state->subtype == SMALLBASKET_SUBTYPE_RANDOM) {
        health = (f32)Player_GetCurrentHealth((int)player);
        healthPercent = health;
        maxHealth = (f32)Player_GetMaxHealth((int)player);
        healthPercent = healthPercent / maxHealth;
        healthPercent = healthPercent * gSmallBasketPercentScale[0];
        if (healthPercent <= gSmallBasketHealthPercentLow[0]) {
            subtypeChoice = SMALLBASKET_SUBTYPE_APPLE;
        } else if (healthPercent <= gSmallBasketHealthPercentHigh[0]) {
            if (randomGetRange(0, (s16)(int)(healthPercent - gSmallBasketHealthPercentLow[0])) < 7) {
                subtypeChoice = SMALLBASKET_SUBTYPE_APPLE;
                maxCount = (s16)(maxHealth * gSmallBasketQuarter[0]);
                if (maxCount < 1) {
                    maxCount = 1;
                }
                randomGetRange(1, maxCount);
            } else {
                subtypeChoice = SMALLBASKET_SUBTYPE_GREEN_SCARAB;
                randomGetRange(1, 4);
            }
        } else {
            return 1;
        }
    } else {
        subtypeChoice = state->subtype;
    }

    selectedSubtype = subtypeChoice;
    collisionVelocity = gSmallBasketHitVelocity;
    switch (selectedSubtype) {
    case SMALLBASKET_SUBTYPE_GREEN_SCARAB:
        childPlacement = (u8*)Obj_AllocObjectSetup(SCARAB_PLACEMENT_SIZE, SCARAB_OBJECT_GREEN);
        ((ObjPlacement*)childPlacement)->posX = obj->anim.localPosX;
        ((ObjPlacement*)childPlacement)->posY = obj->anim.localPosY;
        ((ObjPlacement*)childPlacement)->posZ = obj->anim.localPosZ;
        ((ScarabPlacement*)childPlacement)->activeTimer = 0x190;
        child = (u8*)Obj_SetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        if (useHitVelocity) {
            burstScale = gSmallBasketBurstVelocityXZ[0];
            ((GameObject*)child)->anim.velocityX = burstScale * gSmallBasketHitVelocity[0];
            ((GameObject*)child)->anim.velocityY = gSmallBasketBurstVelocityY[0] * hitVelocity[1];
            ((GameObject*)child)->anim.velocityZ = burstScale * collisionVelocity[2];
        } else {
            ((GameObject*)child)->anim.velocityX = obj->anim.localPosX - playerRef->anim.localPosX;
            ((GameObject*)child)->anim.velocityZ = obj->anim.localPosZ - playerRef->anim.localPosZ;
        }
        horizontalMagnitude = ((GameObject*)child)->anim.velocityX * ((GameObject*)child)->anim.velocityX;
        horizontalMagnitude += ((GameObject*)child)->anim.velocityZ * ((GameObject*)child)->anim.velocityZ;
        if (horizontalMagnitude != gSmallBasketZero[0]) {
            horizontalMagnitude = sqrtf(horizontalMagnitude);
            ((GameObject*)child)->anim.velocityX = ((GameObject*)child)->anim.velocityX / horizontalMagnitude;
            ((GameObject*)child)->anim.velocityZ = ((GameObject*)child)->anim.velocityZ / horizontalMagnitude;
        }
        ((GameObject*)child)->anim.velocityX =
            ((GameObject*)child)->anim.velocityX *
            -(gSmallBasketVelocityStep[0] * (f32)randomGetRange(0, 0x19) - gSmallBasketOne[0]);
        ((GameObject*)child)->anim.velocityZ =
            ((GameObject*)child)->anim.velocityZ *
            -(gSmallBasketVelocityStep[0] * (f32)randomGetRange(0, 0x19) - gSmallBasketOne[0]);
        ((GameObject*)child)->anim.velocityY = gSmallBasketThrowVelocityY[0];
        rotation.posX = gSmallBasketZero[0];
        rotation.posY = gSmallBasketZero[0];
        rotation.posZ = gSmallBasketZero[0];
        rotation.scale = gSmallBasketOne[0];
        rotation.rotZ = 0;
        rotation.rotY = 0;
        rotation.rotX = randomGetRange(-10000, 10000);
        vecRotateZXY(&rotation.rotX, (f32*)(child + 0x24));
        heading = (u16)(s16)getAngle(((GameObject*)child)->anim.velocityX, -((GameObject*)child)->anim.velocityZ);
        angleDelta = ((GameObject*)child)->anim.rotX - heading;
        if (angleDelta > SMALLBASKET_YAW_HALF_TURN) {
            angleDelta -= SMALLBASKET_YAW_WRAP;
        }
        if (angleDelta < -SMALLBASKET_YAW_HALF_TURN) {
            angleDelta += SMALLBASKET_YAW_WRAP;
        }
        ((GameObject*)child)->anim.rotX = angleDelta;
        break;
    case SMALLBASKET_SUBTYPE_RED_SCARAB:
        childPlacement = (u8*)Obj_AllocObjectSetup(SCARAB_PLACEMENT_SIZE, SCARAB_OBJECT_RED);
        ((ScarabPlacement*)childPlacement)->yawByte = randomGetRange(-0x7F, 0x7E);
        ((ObjPlacement*)childPlacement)->posX = obj->anim.localPosX;
        ((ObjPlacement*)childPlacement)->posY = obj->anim.localPosY;
        ((ObjPlacement*)childPlacement)->posZ = obj->anim.localPosZ;
        ((ScarabPlacement*)childPlacement)->activeTimer = 0x190;
        child = (u8*)Obj_SetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        if (useHitVelocity) {
            burstScale = gSmallBasketBurstVelocityXZ[0];
            ((GameObject*)child)->anim.velocityX = burstScale * gSmallBasketHitVelocity[0];
            ((GameObject*)child)->anim.velocityY = gSmallBasketBurstVelocityY[0] * hitVelocity[1];
            ((GameObject*)child)->anim.velocityZ = burstScale * collisionVelocity[2];
        } else {
            ((GameObject*)child)->anim.velocityX = obj->anim.localPosX - playerRef->anim.localPosX;
            ((GameObject*)child)->anim.velocityZ = obj->anim.localPosZ - playerRef->anim.localPosZ;
        }
        horizontalMagnitude = ((GameObject*)child)->anim.velocityX * ((GameObject*)child)->anim.velocityX;
        horizontalMagnitude += ((GameObject*)child)->anim.velocityZ * ((GameObject*)child)->anim.velocityZ;
        if (horizontalMagnitude != gSmallBasketZero[0]) {
            horizontalMagnitude = sqrtf(horizontalMagnitude);
            ((GameObject*)child)->anim.velocityX = ((GameObject*)child)->anim.velocityX / horizontalMagnitude;
            ((GameObject*)child)->anim.velocityZ = ((GameObject*)child)->anim.velocityZ / horizontalMagnitude;
        }
        ((GameObject*)child)->anim.velocityX =
            ((GameObject*)child)->anim.velocityX *
            -(gSmallBasketVelocityStep[0] * (f32)randomGetRange(0, 0x19) - gSmallBasketOne[0]);
        ((GameObject*)child)->anim.velocityZ =
            ((GameObject*)child)->anim.velocityZ *
            -(gSmallBasketVelocityStep[0] * (f32)randomGetRange(0, 0x19) - gSmallBasketOne[0]);
        ((GameObject*)child)->anim.velocityY = gSmallBasketThrowVelocityY[0];
        rotation.posX = gSmallBasketZero[0];
        rotation.posY = gSmallBasketZero[0];
        rotation.posZ = gSmallBasketZero[0];
        rotation.scale = gSmallBasketOne[0];
        rotation.rotZ = 0;
        rotation.rotY = 0;
        rotation.rotX = randomGetRange(-10000, 10000);
        vecRotateZXY(&rotation.rotX, (f32*)(child + 0x24));
        heading = (u16)(s16)getAngle(((GameObject*)child)->anim.velocityX, -((GameObject*)child)->anim.velocityZ);
        angleDelta = ((GameObject*)child)->anim.rotX - heading;
        if (angleDelta > SMALLBASKET_YAW_HALF_TURN) {
            angleDelta -= SMALLBASKET_YAW_WRAP;
        }
        if (angleDelta < -SMALLBASKET_YAW_HALF_TURN) {
            angleDelta += SMALLBASKET_YAW_WRAP;
        }
        ((GameObject*)child)->anim.rotX = angleDelta;
        break;
    case SMALLBASKET_SUBTYPE_GOLD_SCARAB:
        childPlacement = (u8*)Obj_AllocObjectSetup(SCARAB_PLACEMENT_SIZE, SCARAB_OBJECT_GOLD);
        ((ScarabPlacement*)childPlacement)->yawByte = randomGetRange(-0x7F, 0x7E);
        ((ObjPlacement*)childPlacement)->posX = obj->anim.localPosX;
        ((ObjPlacement*)childPlacement)->posY = obj->anim.localPosY;
        ((ObjPlacement*)childPlacement)->posZ = obj->anim.localPosZ;
        ((ScarabPlacement*)childPlacement)->activeTimer = 0x7D0;
        child = (u8*)Obj_SetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        if (useHitVelocity) {
            burstScale = gSmallBasketBurstVelocityXZ[0];
            ((GameObject*)child)->anim.velocityX = burstScale * gSmallBasketHitVelocity[0];
            ((GameObject*)child)->anim.velocityY = gSmallBasketBurstVelocityY[0] * hitVelocity[1];
            ((GameObject*)child)->anim.velocityZ = burstScale * collisionVelocity[2];
        } else {
            ((GameObject*)child)->anim.velocityX = obj->anim.localPosX - playerRef->anim.localPosX;
            ((GameObject*)child)->anim.velocityZ = obj->anim.localPosZ - playerRef->anim.localPosZ;
        }
        horizontalMagnitude = ((GameObject*)child)->anim.velocityX * ((GameObject*)child)->anim.velocityX;
        horizontalMagnitude += ((GameObject*)child)->anim.velocityZ * ((GameObject*)child)->anim.velocityZ;
        if (horizontalMagnitude != gSmallBasketZero[0]) {
            horizontalMagnitude = sqrtf(horizontalMagnitude);
            ((GameObject*)child)->anim.velocityX = ((GameObject*)child)->anim.velocityX / horizontalMagnitude;
            ((GameObject*)child)->anim.velocityZ = ((GameObject*)child)->anim.velocityZ / horizontalMagnitude;
        }
        ((GameObject*)child)->anim.velocityX =
            ((GameObject*)child)->anim.velocityX *
            -(gSmallBasketVelocityStep[0] * (f32)randomGetRange(0, 0x19) - gSmallBasketOne[0]);
        ((GameObject*)child)->anim.velocityZ =
            ((GameObject*)child)->anim.velocityZ *
            -(gSmallBasketVelocityStep[0] * (f32)randomGetRange(0, 0x19) - gSmallBasketOne[0]);
        ((GameObject*)child)->anim.velocityY = gSmallBasketThrowVelocityY[0];
        rotation.posX = gSmallBasketZero[0];
        rotation.posY = gSmallBasketZero[0];
        rotation.posZ = gSmallBasketZero[0];
        rotation.scale = gSmallBasketOne[0];
        rotation.rotZ = 0;
        rotation.rotY = 0;
        rotation.rotX = randomGetRange(-10000, 10000);
        vecRotateZXY(&rotation.rotX, (f32*)(child + 0x24));
        heading = (u16)(s16)getAngle(((GameObject*)child)->anim.velocityX, -((GameObject*)child)->anim.velocityZ);
        angleDelta = ((GameObject*)child)->anim.rotX - heading;
        if (angleDelta > SMALLBASKET_YAW_HALF_TURN) {
            angleDelta -= SMALLBASKET_YAW_WRAP;
        }
        if (angleDelta < -SMALLBASKET_YAW_HALF_TURN) {
            angleDelta += SMALLBASKET_YAW_WRAP;
        }
        ((GameObject*)child)->anim.rotX = angleDelta;
        break;
    case SMALLBASKET_SUBTYPE_ENERGY_EGG:
    case SMALLBASKET_SUBTYPE_APPLE:
        if (state->subtype == SMALLBASKET_SUBTYPE_ENERGY_EGG) {
            childPlacement = (u8*)Obj_AllocObjectSetup(0x30, SMALLBASKET_CHILD_OBJECT_ENERGY_EGG);
        } else {
            childPlacement = (u8*)Obj_AllocObjectSetup(0x30, SMALLBASKET_CHILD_OBJECT_APPLE);
        }
        ((CollectibleSetup*)childPlacement)->unk1A = 0x14;
        ((CollectibleSetup*)childPlacement)->counterGameBit = -1;
        ((CollectibleSetup*)childPlacement)->hideGameBit = -1;
        if (state->throwState != SMALLBASKET_THROW_NONE) {
            ((ObjPlacement*)childPlacement)->posX = obj->anim.localPosX + (f32)randomGetRange(-0xF, 0xF);
            ((ObjPlacement*)childPlacement)->posY = (15.0f) + obj->anim.localPosY;
            ((ObjPlacement*)childPlacement)->posZ = obj->anim.localPosZ + (f32)randomGetRange(-0xF, 0xF);
        } else {
            ((ObjPlacement*)childPlacement)->posX = obj->anim.localPosX;
            ((ObjPlacement*)childPlacement)->posY = (5.0f) + obj->anim.localPosY;
            ((ObjPlacement*)childPlacement)->posZ = obj->anim.localPosZ;
        }
        ((CollectibleSetup*)childPlacement)->visibilityGameBit = -1;
        child = (u8*)Obj_SetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        if (useHitVelocity) {
            burstScale = gSmallBasketBurstVelocityXZ[0];
            ((GameObject*)child)->anim.velocityX = burstScale * gSmallBasketHitVelocity[0];
            ((GameObject*)child)->anim.velocityY = gSmallBasketBurstVelocityY[0] * hitVelocity[1];
            ((GameObject*)child)->anim.velocityZ = burstScale * collisionVelocity[2];
        }
        horizontalMagnitude = ((GameObject*)child)->anim.velocityX * ((GameObject*)child)->anim.velocityX;
        horizontalMagnitude += ((GameObject*)child)->anim.velocityZ * ((GameObject*)child)->anim.velocityZ;
        if (horizontalMagnitude != gSmallBasketZero[0]) {
            horizontalMagnitude = sqrtf(horizontalMagnitude);
            ((GameObject*)child)->anim.velocityX =
                ((GameObject*)child)->anim.velocityX / (horizontalMagnitude = (2.0f) * horizontalMagnitude);
            ((GameObject*)child)->anim.velocityZ = ((GameObject*)child)->anim.velocityZ / horizontalMagnitude;
        }
        ((GameObject*)child)->anim.velocityX =
            ((GameObject*)child)->anim.velocityX *
            -(gSmallBasketVelocityStep[0] * (f32)randomGetRange(0, 0x19) - gSmallBasketOne[0]);
        ((GameObject*)child)->anim.velocityZ =
            ((GameObject*)child)->anim.velocityZ *
            -(gSmallBasketVelocityStep[0] * (f32)randomGetRange(0, 0x19) - gSmallBasketOne[0]);
        ((GameObject*)child)->anim.velocityY = gSmallBasketThrowVelocityY[0];
        (*(CollectibleInterface**)((GameObject*)child)->anim.dll)
            ->startBounceMotion((GameObject*)child, ((GameObject*)child)->anim.velocityX,
                                ((GameObject*)child)->anim.velocityY, ((GameObject*)child)->anim.velocityZ);
        rotation.posX = gSmallBasketZero[0];
        rotation.posY = gSmallBasketZero[0];
        rotation.posZ = gSmallBasketZero[0];
        rotation.scale = gSmallBasketOne[0];
        rotation.rotZ = 0;
        rotation.rotY = 0;
        rotation.rotX = randomGetRange(-10000, 10000);
        vecRotateZXY(&rotation.rotX, (f32*)(child + 0x24));
        heading = (u16)(s16)getAngle(((GameObject*)child)->anim.velocityX, -((GameObject*)child)->anim.velocityZ);
        angleDelta = ((GameObject*)child)->anim.rotX - heading;
        if (angleDelta > SMALLBASKET_YAW_HALF_TURN) {
            angleDelta -= SMALLBASKET_YAW_WRAP;
        }
        if (angleDelta < -SMALLBASKET_YAW_HALF_TURN) {
            angleDelta += SMALLBASKET_YAW_WRAP;
        }
        ((GameObject*)child)->anim.rotX = angleDelta;
        break;
    }
    return 1;
}

int SmallBasket_resolveCollision(GameObject* obj) {
    ObjHitsPriorityState* hitState;
    s8* hitAxes;
    f32* endPointY;
    f32* endPointZ;
    int hitIndex;
    u8 hitMask;
    f32 zero;
    SmallBasketCollisionResults hitResults;
    f32 endPoints[12];
    f32 startPoints[12];
    TrackQueryBounds sweptBounds;

    hitState = *(ObjHitsPriorityState**)&obj->anim.hitReactState;
    if (objBboxFn_800640cc(&obj->anim.previousLocalPosX, &obj->anim.localPosX, (0.1f), 1, NULL, obj, 1, -1,
                           SMALLBASKET_TRACK_MASK, 0) != 0) {
        hitState->contactFlags |= OBJHITS_CONTACT_FLAG_KIND0;
        hitState->localPosX = obj->anim.previousLocalPosX;
        hitState->localPosY = obj->anim.previousLocalPosY;
        hitState->localPosZ = obj->anim.previousLocalPosZ;
        zero = gSmallBasketZero[0];
        obj->anim.velocityX = zero;
        obj->anim.velocityY = zero;
        obj->anim.velocityZ = zero;
        return 1;
    }

    if ((int)(hitState->objectHitMask >> 4) != 0 && hitState->suppressOutgoingHits == 0) {
        endPoints[0] = obj->anim.localPosX;
        *(endPointY = &endPoints[1]) = obj->anim.localPosY;
        *(endPointZ = &endPoints[2]) = obj->anim.localPosZ;
        startPoints[0] = obj->anim.previousLocalPosX;
        startPoints[1] = obj->anim.previousLocalPosY;
        startPoints[2] = obj->anim.previousLocalPosZ;
        hitResults.radii[0] = (f32)hitState->primaryRadius;
        *(hitAxes = hitResults.hitAxes) = -1;
        hitAxes[4] = 3;
    } else {
        return 0;
    }

    hitDetect_calcSweptSphereBounds(&sweptBounds, startPoints, endPoints, hitResults.radii, 1);
    hitDetectFn_800691c0(obj, &sweptBounds, hitState->trackContactMask, 1);
    hitMask = hitDetectFn_80067958(obj, startPoints, endPoints, 1, &hitResults, 0);
    if (hitMask != 0) {
        if (hitMask & 1) {
            hitIndex = 0;
        } else if (hitMask & 2) {
            hitIndex = 1;
        } else if (hitMask & 4) {
            hitIndex = 2;
        } else {
            hitIndex = 3;
        }
        hitState->contactHitVolume = hitAxes[hitIndex];
        hitState->contactPosX = endPoints[hitIndex * 3];
        hitState->contactPosY = endPointY[hitIndex * 3];
        hitState->contactPosZ = endPointZ[hitIndex * 3];
        gSmallBasketHitVelocity[0] = hitResults.hitInfo[hitIndex][0];
        gSmallBasketHitVelocity[1] = hitResults.hitInfo[hitIndex][1];
        gSmallBasketHitVelocity[2] = hitResults.hitInfo[hitIndex][2];
        gSmallBasketHitVelocity[3] = hitResults.hitInfo[hitIndex][3];
        if (hitResults.solidFlags[hitIndex] != 0) {
            hitState->contactFlags |= OBJHITS_CONTACT_FLAG_KIND_NONZERO;
            obj->anim.localPosX = hitState->contactPosX;
            obj->anim.localPosY = hitState->contactPosY;
            obj->anim.localPosZ = hitState->contactPosZ;
            hitState->localPosX = obj->anim.previousLocalPosX;
            hitState->localPosY = obj->anim.previousLocalPosY;
            hitState->localPosZ = obj->anim.previousLocalPosZ;
            zero = gSmallBasketZero[0];
            obj->anim.velocityX = zero;
            obj->anim.velocityY = zero;
            obj->anim.velocityZ = zero;
            return 1;
        } else {
            hitState->contactFlags |= OBJHITS_CONTACT_FLAG_KIND0;
            obj->anim.localPosX = hitState->contactPosX;
            obj->anim.localPosY = hitState->contactPosY;
            obj->anim.localPosZ = hitState->contactPosZ;
            hitState->localPosX = obj->anim.previousLocalPosX;
            hitState->localPosY = obj->anim.previousLocalPosY;
            hitState->localPosZ = obj->anim.previousLocalPosZ;
            zero = gSmallBasketZero[0];
            obj->anim.velocityX = zero;
            obj->anim.velocityY = zero;
            obj->anim.velocityZ = zero;
            return 1;
        }
    }
    return 0;
}

void SmallBasket_throw(GameObject* obj) {
    PartFxSpawnParams rotation;
    SmallBasketState* state;
    GameObject* player;

    state = *(SmallBasketState**)&obj->extra;
    player = Obj_GetPlayerObject();
    state->carryAttached = 0;
    state->carryState = SMALLBASKET_CARRY_IDLE;
    state->throwState = SMALLBASKET_THROW_LAUNCHED;
    obj->anim.velocityY = gSmallBasketThrowVelocityY[0];
    obj->anim.velocityZ = (-2.2f);
    rotation.posX = gSmallBasketZero[0];
    rotation.posY = gSmallBasketZero[0];
    rotation.posZ = gSmallBasketZero[0];
    rotation.scale = gSmallBasketOne[0];
    rotation.rotZ = 0;
    rotation.rotY = 0;
    rotation.rotX = player->anim.rotX;
    vecRotateZXY(&rotation.rotX, &obj->anim.velocityX);
}

int SmallBasket_getExtraSize(void) {
    return sizeof(SmallBasketState);
}

void SmallBasket_free(GameObject* obj) {
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(gSmallBasketResource);
    ObjGroup_RemoveObject((int)obj, SMALLBASKET_OBJECT_GROUP);
}

void SmallBasket_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    SmallBasketState* state;
    SmallBasketPlacement* placement;
    int mapTimeActive;
    s16 disableTimer;

    state = *(SmallBasketState**)&obj->extra;
    placement = *(SmallBasketPlacement**)&obj->anim.placementData;
    mapTimeActive = (*gMapEventInterface)->shouldNotSaveTime(placement->base.mapId);
    if (mapTimeActive == 0) {
        obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
    } else {
        disableTimer = state->disableTimer;
        if ((disableTimer != 0 && disableTimer <= SMALLBASKET_HIT_DISABLE_FRAMES) || state->hiddenTimer != 0) {
            obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
        } else if (obj->userData2 != 0 && visible != -1) {
            obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
        } else {
            objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, gSmallBasketOne[0]);
        }
    }
}

void SmallBasket_update(GameObject* obj) {
    GameObject* player;
    SmallBasketPlacement* placement;
    SmallBasketState* state;
    PlayerState* playerState;
    int nextState[1];
    s8 contactFlags;
    u8 subtype;
    int alpha;
    f32 zero;
    f32 clockScale;
    PartFxSpawnParams effectParams;

    player = Obj_GetPlayerObject();
    placement = *(SmallBasketPlacement**)&obj->anim.placementData;
    clockScale = gSmallBasketOne[0];
    (*gSkyInterface)->getClockTime(&clockScale);
    state = obj->extra;
    if ((*gMapEventInterface)->shouldNotSaveTime(placement->base.mapId) == 0) {
        return;
    }
    playerState = player->extra;
    if (state->flightTimer <= 0) {
        state->flightTimer = SMALLBASKET_FLIGHT_FRAMES;
        state->disableTimer = 1;
        state->throwState = SMALLBASKET_THROW_NONE;
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        SmallBasket_spawnContents(obj, player, state);
        zero = gSmallBasketZero[0];
        obj->anim.velocityX = zero;
        obj->anim.velocityZ = zero;
    }
    if (state->hiddenTimer != 0) {
        nextState[0] = 0;
        obj->anim.alpha = nextState[0];
        state->hiddenTimer -= (s16)(int)(timeDelta * clockScale);
        if (state->hiddenTimer <= 0) {
            if ((Vec_distance(&obj->anim.worldPosX, &((GameObject*)Obj_GetPlayerObject())->anim.worldPosX) >
                 SMALLBASKET_RESPAWN_MIN_DISTANCE) &&
                (state->enableGameBit == -1)) {
                nextState[0] = 1;
            }
            if (nextState[0] == 0) {
                state->hiddenTimer = 1;
            } else {
                state->hiddenTimer = 0;
                state->disableTimer = 0;
                ObjHits_EnableObject(obj);
                ObjHits_SyncObjectPositionIfDirty(obj);
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            }
        }
    } else {
        if (state->carryState != SMALLBASKET_CARRY_HELD) {
            alpha = (int)(SMALLBASKET_FADE_STEP * timeDelta + (f32)(u32)obj->anim.alpha);
            if (alpha > SMALLBASKET_ALPHA_MAX) {
                alpha = SMALLBASKET_ALPHA_MAX;
            }
            obj->anim.alpha = alpha;
        }
        if (state->disableTimer != 0) {
            ObjHits_DisableObject(obj);
            state->disableTimer -= framesThisStep;
            if (state->disableTimer <= 0) {
                if (state->respawnDelay != 0) {
                    state->hiddenTimer = state->respawnDelay;
                } else {
                    state->hiddenTimer = 1;
                }
                (*gMapEventInterface)->addTime(placement->base.mapId, (f32)state->respawnDelay);
                obj->anim.localPosX = placement->base.posX;
                obj->anim.localPosY = placement->base.posY;
                obj->anim.localPosZ = placement->base.posZ;
                obj->anim.previousLocalPosX = placement->base.posX;
                obj->anim.previousLocalPosY = placement->base.posY;
                obj->anim.previousLocalPosZ = placement->base.posZ;
                zero = gSmallBasketZero[0];
                obj->anim.velocityX = zero;
                obj->anim.velocityY = zero;
                obj->anim.velocityZ = zero;
            }
            if (state->disableTimer <= SMALLBASKET_HIT_DISABLE_FRAMES) {
                return;
            }
        }
        if (state->throwState != SMALLBASKET_THROW_LAUNCHED) {
            if (state->carryState == SMALLBASKET_CARRY_IDLE) {
                nextState[0] = 0;
                if (((buttonGetDisabled(0) & PAD_BUTTON_A) == 0) && (obj->userData2 == 0) &&
                    (ObjTrigger_IsSet((int)obj) != 0)) {
                    state->carryAngle = -0x8000;
                    state->carryParam = 0;
                    ObjHits_DisableObject(obj);
                    nextState[0] = 1;
                }
                state->carryState = nextState[0];
                if (state->carryState != SMALLBASKET_CARRY_IDLE) {
                    state->carryAttached = 1;
                }
                if (obj->userData2 == 0) {
                    ObjHits_EnableObject(obj);
                    if ((state->disguiseGated != 0) && (playerIsDisguised(player) == 0)) {
                        obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                    } else {
                        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
                    }
                }
                obj->anim.previousLocalPosX = obj->anim.localPosX;
                obj->anim.previousLocalPosY = obj->anim.localPosZ;
                obj->anim.previousLocalPosZ = obj->anim.localPosZ;
            } else {
                ObjHits_DisableObject(obj);
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                if ((playerGetStateFlag310(player) & PLAYER_STATE_FLAG_CAN_PLACE_CARRYABLE) != 0) {
                    setAButtonIcon(A_BUTTON_ICON_PLACE_CARRYABLE);
                } else {
                    setAButtonIcon(A_BUTTON_ICON_THROW_CARRYABLE);
                }
                if ((getButtonsJustPressed(0) & PAD_BUTTON_A) != 0) {
                    if (isTrickyNear(player) != 0) {
                        state->carryAttached = 0;
                        buttonDisable(0, PAD_BUTTON_A);
                    } else {
                        Sfx_PlayFromObject(0, SFXTRIG_id_10a);
                    }
                }
                if (obj->userData2 == 1) {
                    state->carryState = SMALLBASKET_CARRY_HELD;
                }
                if (((state->carryState == SMALLBASKET_CARRY_HELD) && (obj->userData2 == 0)) ||
                    ((state->disguiseGated != 0) && (playerIsDisguised(player) == 0))) {
                    if (fn_8029669C(player) != 0) {
                        state->carryState = SMALLBASKET_CARRY_IDLE;
                        state->throwState = SMALLBASKET_THROW_LAUNCHED;
                        obj->anim.velocityY =
                            (0.75f) * playerState->baddie.inputMagnitude + gSmallBasketThrowVelocityY[0];
                        obj->anim.velocityZ = (-0.75f) * playerState->baddie.inputMagnitude + (-2.2f);
                        effectParams.posX = gSmallBasketZero[0];
                        effectParams.posY = gSmallBasketZero[0];
                        effectParams.posZ = gSmallBasketZero[0];
                        effectParams.scale = gSmallBasketOne[0];
                        effectParams.rotZ = 0;
                        effectParams.rotY = 0;
                        effectParams.rotX = player->anim.rotX;
                        if (player->anim.parent != NULL) {
                            effectParams.rotX = effectParams.rotX + ((ObjAnimComponent*)player->anim.parent)->rotX;
                        }
                        vecRotateZXY((s16*)&effectParams, &obj->anim.velocityX);
                        Sfx_PlayFromObject((int)obj, SFXTRIG_barrel_throw);
                    } else if (fn_802966B4(player) != 0) {
                        state->carryState = SMALLBASKET_CARRY_IDLE;
                        state->throwState = SMALLBASKET_THROW_DROPPED;
                        zero = gSmallBasketZero[0];
                        obj->anim.velocityX = zero;
                        obj->anim.velocityY = zero;
                        obj->anim.velocityZ = zero;
                        ObjHits_EnableObject(obj);
                        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
                    } else {
                        state->carryState = SMALLBASKET_CARRY_IDLE;
                        state->throwState = SMALLBASKET_THROW_LAUNCHED;
                        obj->anim.velocityY = (0.35f) * playerState->baddie.inputMagnitude + (1.2f);
                        obj->anim.velocityZ = (-0.35f) * playerState->baddie.inputMagnitude + (-1.2f);
                        effectParams.posX = gSmallBasketZero[0];
                        effectParams.posY = gSmallBasketZero[0];
                        effectParams.posZ = gSmallBasketZero[0];
                        effectParams.scale = gSmallBasketOne[0];
                        effectParams.rotZ = 0;
                        effectParams.rotY = 0;
                        effectParams.rotX = player->anim.rotX;
                        vecRotateZXY((s16*)&effectParams, &obj->anim.velocityX);
                        Sfx_PlayFromObject((int)obj, SFXTRIG_barrel_throw);
                        state->carryAttached = 0;
                        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                    }
                }
                if (state->carryAttached != 0) {
                    state->disableTimer = 0;
                    state->hiddenTimer = 0;
                    ObjMsg_SendToObject(player, SMALLBASKET_MSG_PLAYER_GRAB, obj,
                                        (state->carryParam << 16) | ((u16)state->carryAngle));
                }
            }
        } else if (state->throwState != SMALLBASKET_THROW_NONE) {
            state->flightTimer -= framesThisStep;
            if (state->throwState == SMALLBASKET_THROW_LAUNCHED) {
                ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, SMALLBASKET_HIT_VOLUME_SLOT, 1, 0);
                if (obj->anim.velocityY > (-10.0f)) {
                    obj->anim.velocityY = -0.12f * timeDelta + obj->anim.velocityY;
                }
                ObjHits_EnableObject(obj);
            }
            obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
            obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
            obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
            SmallBasket_resolveCollision(obj);
            contactFlags = (*(ObjHitsPriorityState**)&obj->anim.hitReactState)->contactFlags;
            if ((contactFlags != 0) && (state->throwState == SMALLBASKET_THROW_LAUNCHED)) {
                effectParams.posX = obj->anim.localPosX;
                effectParams.posY = obj->anim.localPosY;
                effectParams.posZ = obj->anim.localPosZ;
                objLightFn_8009a1dc((void*)obj, gSmallBasketEffectScale[0], &effectParams, 1, 0);
                (*gSmallBasketResource)->spawnBreakEffect(obj, 1, 0, 2, -1, 0);
                Sfx_PlayFromObject((int)obj, (u16)state->hitSfxId);
                state->disableTimer = SMALLBASKET_HIT_DISABLE_FRAMES;
                state->throwState = SMALLBASKET_THROW_NONE;
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                SmallBasket_spawnContents(obj, player, state);
                zero = gSmallBasketZero[0];
                obj->anim.velocityX = zero;
                obj->anim.velocityZ = zero;
                ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
            } else if ((contactFlags != 0) && (state->throwState == SMALLBASKET_THROW_DROPPED)) {
                zero = gSmallBasketZero[0];
                obj->anim.velocityX = zero;
                obj->anim.velocityZ = zero;
                state->disableTimer = SMALLBASKET_RETURN_DISABLE_FRAMES;
                state->throwState = SMALLBASKET_THROW_NONE;
                obj->userData2 = 0;
                ObjHits_EnableObject(obj);
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
            }
        }
        state->ambientSfxTimer -= framesThisStep;
        if (state->carryState != SMALLBASKET_CARRY_IDLE) {
            if (getXZDistance(&obj->anim.worldPosX, &placement->base.posX) >=
                (f32)(state->leashRange * state->leashRange)) {
                zero = gSmallBasketZero[0];
                obj->anim.velocityX = zero;
                obj->anim.velocityZ = zero;
                state->disableTimer = SMALLBASKET_RETURN_DISABLE_FRAMES;
                state->throwState = SMALLBASKET_THROW_NONE;
                obj->userData2 = 0;
                ObjHits_EnableObject(obj);
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
            }
        } else {
            SmallBasket_handleHit(obj, player, state);
        }
        if ((state->ambientSfxTimer <= 0) && (state->carryState != SMALLBASKET_CARRY_IDLE)) {
            subtype = state->subtype;
            if ((subtype == SMALLBASKET_SUBTYPE_ENERGY_EGG) || (subtype == SMALLBASKET_SUBTYPE_APPLE)) {
                Sfx_PlayFromObject((int)obj, SFXTRIG_id_6c);
                state->ambientSfxTimer =
                    (s16)(randomGetRange(0, SMALLBASKET_RANDOM_DELAY_MAX) + SMALLBASKET_RANDOM_DELAY_BASE);
            } else if (((u8)(subtype - SMALLBASKET_SUBTYPE_GREEN_SCARAB) <= 1) ||
                       (subtype == SMALLBASKET_SUBTYPE_GOLD_SCARAB)) {
                Sfx_PlayFromObject((int)obj, SFXTRIG_vineclimb116);
                state->ambientSfxTimer =
                    (s16)(randomGetRange(0, SMALLBASKET_RANDOM_DELAY_MAX) + SMALLBASKET_RANDOM_DELAY_BASE);
            }
        }
        if (obj->userData2 == 0) {
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
    }
}

void SmallBasket_init(GameObject* obj, SmallBasketPlacement* placement) {
    SmallBasketState* state;
    s16 respawnMinutes;
    s16 sequenceId;

    state = obj->extra;
    ObjHits_DisableObject(obj);
    ObjGroup_AddObject((int)obj, SMALLBASKET_OBJECT_GROUP);

    respawnMinutes = placement->respawnMinutes;
    if (respawnMinutes == 0) {
        state->respawnDelay = 0;
    } else {
        state->respawnDelay = respawnMinutes * SMALLBASKET_FRAMES_PER_MINUTE;
    }

    gSmallBasketResource = Resource_Acquire(SMALLBASKET_RESOURCE_ID, SMALLBASKET_RESOURCE_COUNT);
    state->ambientSfxTimer = (s16)(randomGetRange(0, SMALLBASKET_RANDOM_DELAY_MAX) + SMALLBASKET_RANDOM_DELAY_BASE);
    state->unk1F = (u8)placement->unk1A;
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    state->enableGameBit = placement->enableGameBit;
    state->leashRange = placement->leashRange;
    if (state->leashRange == 0) {
        state->leashRange = SMALLBASKET_DEFAULT_LEASH_RANGE;
    }
    state->flightTimer = SMALLBASKET_FLIGHT_FRAMES;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    state->subtype = placement->subtype;
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosX = obj->anim.localPosZ;

    if (mainGetBit(state->enableGameBit) != 0) {
        state->hiddenTimer = 1;
        ObjHits_DisableObject(obj);
    }

    sequenceId = obj->anim.seqId;
    if (sequenceId == SMALLBASKET_SEQUENCE_VARIANT_A) {
        state->hitSfxId = SMALLBASKET_HIT_SFX_VARIANT_A;
    } else if (sequenceId == SMALLBASKET_SEQUENCE_DISGUISE_GATED) {
        state->disguiseGated = 1;
        state->hitSfxId = SMALLBASKET_HIT_SFX_DISGUISE_GATED;
    } else {
        state->hitSfxId = SMALLBASKET_HIT_SFX_DEFAULT;
    }
}

ObjectDescriptor gSmallBasketObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SmallBasket_init,
    (ObjectDescriptorCallback)SmallBasket_update,
    0,
    (ObjectDescriptorCallback)SmallBasket_render,
    (ObjectDescriptorCallback)SmallBasket_free,
    0,
    SmallBasket_getExtraSize,
};
