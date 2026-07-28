/*
 * DLL 0x105 - LargeCrate.
 *
 * Destructible, optionally respawning crates with variant-specific drops,
 * impact effects, and conveyor-platform movement.
 */
#include "dlls/objects/261_LargeCrate.h"
#include "dlls/objects/237.h"
#include "dlls/objects/262.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define LARGECRATE_LINKED_ID_BASE       0x40000
#define LARGECRATE_ROB_WAVE_DIRECT_ID   0x66
#define LARGECRATE_ROB_WAVE_ID_65D0     0x65D0
#define LARGECRATE_ROB_WAVE_ID_65D2     0x65D2
#define LARGECRATE_ROB_WAVE_ID_65D5     0x65D5
#define LARGECRATE_ROB_WAVE_ID_65D6     0x65D6
#define LARGECRATE_ROB_WAVE_ID_65D7     0x65D7
#define LARGECRATE_GAMEBIT_SFX_MUTE     0xA71

#define LARGECRATE_RESPAWN_FRAMES_PER_MINUTE 0x3C
#define LARGECRATE_RESPAWN_DISABLED          0
#define LARGECRATE_RESPAWN_PERMANENT         0xFF
#define LARGECRATE_RESOURCE_ID               0x5B
#define LARGECRATE_RESOURCE_COUNT            1
#define LARGECRATE_RANDOM_DELAY_MIN          0
#define LARGECRATE_RANDOM_DELAY_MAX          100
#define LARGECRATE_RANDOM_DELAY_BASE         300
#define LARGECRATE_UNK_0C_INITIAL            0x190
#define LARGECRATE_RANDOM_SLIDE_PHASE_MAX    200

#define LARGECRATE_CHILD_OBJECT_ENERGY_EGG COLLECTIBLE_ITEM_ENERGY_EGG
#define LARGECRATE_CHILD_OBJECT_APPLE      COLLECTIBLE_ITEM_APPLE
#define LARGECRATE_CHILD_OBJECT_PICKUP     0x259
#define LARGECRATE_PICKUP_PLACEMENT_SIZE   0x24

#define LARGECRATE_SEQUENCE_VARIANT_A  0x3DE
#define LARGECRATE_SEQUENCE_VARIANT_B  0x49F
#define LARGECRATE_SEQUENCE_VARIANT_C  0x7BE
#define LARGECRATE_VARIANT_A_HIT_SFX   0x5F
#define LARGECRATE_VARIANT_A_BREAK_SFX 0x60
#define LARGECRATE_VARIANT_B_HIT_SFX   0x48
#define LARGECRATE_VARIANT_B_BREAK_SFX 0x4A

#define LARGECRATE_BREAK_FRAMES              0x32
#define LARGECRATE_MODEL_FADE_FRAMES         300
#define LARGECRATE_ALPHA_MAX                 0xFF
#define LARGECRATE_FADE_STEP                 8.0f
#define LARGECRATE_EFFECT_SCALE              0.014f
#define LARGECRATE_WARNING_DISTANCE          200.0f
#define LARGECRATE_RESPAWN_DISTANCE          100.0f
#define LARGECRATE_YAW_HALF_TURN             0x8000
#define LARGECRATE_YAW_WRAP                  0xFFFF
#define LARGECRATE_CHILD_RANDOM_VELOCITY_MAX 0x19
#define LARGECRATE_SPIN_SPEED_MIN            600
#define LARGECRATE_SPIN_SPEED_MAX            800

typedef void (*LargeCrateBreakEffectFn)(GameObject* obj, int arg1, int arg2, int arg3, int arg4, int arg5);

typedef struct LargeCrateVariantRemap {
    s16 entries[6];
} LargeCrateVariantRemap;

typedef struct LargeCrateResource {
    void* pad00;
    LargeCrateBreakEffectFn spawnBreakEffect; /* 0x04 */
} LargeCrateResource;

const LargeCrateVariantRemap gLargeCrateVariantARemap = {
    {0, 1, 2, 3, 4, 8},
};
const LargeCrateVariantRemap gLargeCrateVariantBRemap = {
    {0, 5, 6, 7, 8, 9},
};

STATIC_ASSERT(sizeof(LargeCrateVariantRemap) == 0xC);
STATIC_ASSERT(offsetof(LargeCrateResource, pad00) == 0x0);
STATIC_ASSERT(offsetof(LargeCrateResource, spawnBreakEffect) == 0x4);
STATIC_ASSERT(sizeof(LargeCrateResource) == 0x8);

LargeCrateResource** gLargeCrateResource;

ObjectDescriptor gLargeCrateObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)LargeCrate_initialise,
    (ObjectDescriptorCallback)LargeCrate_release,
    0,
    (ObjectDescriptorCallback)LargeCrate_init,
    (ObjectDescriptorCallback)LargeCrate_update,
    (ObjectDescriptorCallback)LargeCrate_hitDetect,
    (ObjectDescriptorCallback)LargeCrate_render,
    (ObjectDescriptorCallback)LargeCrate_free,
    (ObjectDescriptorCallback)LargeCrate_getObjectTypeId,
    LargeCrate_getExtraSize,
};

/* Superset of the 0x24- and 0x30-byte placement records used by crate drops. */
typedef struct LargeCratePickupPlacement {
    ObjPlacement base; /* 0x00 */
    u8 pad18[2];       /* 0x18 */
    s16 unk1A;         /* 0x1A */
    u8 pad1C[4];       /* 0x1C */
    s16 unk20;         /* 0x20 */
    u8 pad22[2];       /* 0x22 */
} LargeCratePickupPlacement;

STATIC_ASSERT(offsetof(LargeCratePickupPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(LargeCratePickupPlacement, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(LargeCratePickupPlacement, unk20) == 0x20);
STATIC_ASSERT(sizeof(LargeCratePickupPlacement) == LARGECRATE_PICKUP_PLACEMENT_SIZE);

static void LargeCrate_spawnPickup(GameObject* obj) {
    char* childPlacement;

    if (Obj_IsLoadingLocked() != 0) {
        childPlacement = (char*)Obj_AllocObjectSetup(LARGECRATE_PICKUP_PLACEMENT_SIZE, LARGECRATE_CHILD_OBJECT_PICKUP);
        ((LargeCratePickupPlacement*)childPlacement)->base.posX = obj->anim.localPosX;
        ((LargeCratePickupPlacement*)childPlacement)->base.posY = 2.0f + obj->anim.localPosY;
        ((LargeCratePickupPlacement*)childPlacement)->base.posZ = obj->anim.localPosZ;
        ((LargeCratePickupPlacement*)childPlacement)->base.color[0] = 4;
        ((LargeCratePickupPlacement*)childPlacement)->base.color[2] = 200;
        ((LargeCratePickupPlacement*)childPlacement)->unk20 = -1;
        ((LargeCratePickupPlacement*)childPlacement)->unk1A = 0x7F;
        Obj_SetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1, (void*)*(int*)&obj->anim.parent);
    }
}

f32 LargeCrate_getReticleDistance(GameObject* obj) {
    LargeCrateState* state = obj->extra;
    return 1.0f - (f32)(u32)state->damageTaken / (f32)(u32)state->damageThreshold;
}

void LargeCrate_updateConveyorSlide(GameObject* obj, LargeCrateState* state) {
    ObjPlacement* placement;
    GameObject* player;
    GameObject* parent;
    f32 previousVelocityX;
    int slideAngle;
    u32 linkedIdOffset;
    u32 linkedId;
    f32 positionLimit;

    placement = (ObjPlacement*)obj->anim.placementData;
    player = Obj_GetPlayerObject();
    parent = obj->anim.parent;
    if ((parent->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0) {
        obj->anim.localPosX = state->homeX;
        obj->anim.velocityX = 0.0f;
    } else {
        previousVelocityX = obj->anim.velocityX;
        slideAngle = parent->anim.rotZ + state->slideOffset;
        obj->anim.velocityX = -(f32)slideAngle / state->slidePhase;
        if ((previousVelocityX <= 0.0f && obj->anim.velocityX >= 0.0f) ||
            (previousVelocityX >= 0.0f && obj->anim.velocityX <= 0.0f)) {
            linkedId = placement->mapId;
            linkedIdOffset = linkedId - LARGECRATE_LINKED_ID_BASE;
            if ((linkedIdOffset == LARGECRATE_ROB_WAVE_ID_65D7) ||
                ((linkedIdOffset - LARGECRATE_ROB_WAVE_ID_65D5) <=
                 (LARGECRATE_ROB_WAVE_ID_65D6 - LARGECRATE_ROB_WAVE_ID_65D5)) ||
                (linkedId == LARGECRATE_ROB_WAVE_DIRECT_ID) || (linkedIdOffset == LARGECRATE_ROB_WAVE_ID_65D0) ||
                (linkedIdOffset == LARGECRATE_ROB_WAVE_ID_65D2)) {
                if (Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX) < LARGECRATE_WARNING_DISTANCE) {
                    if (mainGetBit(LARGECRATE_GAMEBIT_SFX_MUTE) == 0) {
                        Sfx_PlayFromObject((int)obj, SFXTRIG_tr_jbike_snowhit);
                    }
                }
            }
        }
        obj->anim.localPosX = obj->anim.localPosX + obj->anim.velocityX;
        if (obj->anim.localPosX > (positionLimit = 5.0f + state->homeX)) {
            obj->anim.localPosX = positionLimit;
        } else {
            positionLimit = state->homeX - 60.0f;
            if (obj->anim.localPosX < positionLimit) {
                obj->anim.localPosX = positionLimit;
            }
        }
    }
}

static int LargeCrate_isPlayerFar(GameObject* obj) {
    return Vec_distance(&obj->anim.worldPosX, &Obj_GetPlayerObject()->anim.worldPosX) > LARGECRATE_RESPAWN_DISTANCE;
}

int LargeCrate_spawnDropContents(GameObject* obj, GameObject* player, LargeCrateState* state) {
    GameObject* playerRef;
    PartFxSpawnParams rotation;
    char* childPlacement;
    char* child;
    f32 horizontalMagnitude;
    f32 zero;
    int angleDelta;

    zero = 0.0f;
    playerRef = player;
    if (Obj_IsLoadingLocked() == 0) {
        return 0;
    }
    mainSetBits(state->brokenGameBit, 1);
    switch (state->dropType) {
    case LARGECRATE_DROPTYPE_GREEN_SCARAB:
        childPlacement = (char*)Obj_AllocObjectSetup(SCARAB_PLACEMENT_SIZE, SCARAB_OBJECT_GREEN);
        ((ScarabPlacement*)childPlacement)->base.posX = obj->anim.localPosX;
        ((ScarabPlacement*)childPlacement)->base.posY = obj->anim.localPosY;
        ((ScarabPlacement*)childPlacement)->base.posZ = obj->anim.localPosZ;
        ((ScarabPlacement*)childPlacement)->activeTimer = 400;
        child = (char*)Obj_SetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1,
                                       (void*)*(int*)&obj->anim.parent);
        ((GameObject*)child)->anim.velocityX = obj->anim.localPosX - playerRef->anim.localPosX;
        ((GameObject*)child)->anim.velocityZ = obj->anim.localPosZ - playerRef->anim.localPosZ;
        horizontalMagnitude = ((GameObject*)child)->anim.velocityX * ((GameObject*)child)->anim.velocityX +
                              ((GameObject*)child)->anim.velocityZ * ((GameObject*)child)->anim.velocityZ;
        if (horizontalMagnitude != zero) {
            horizontalMagnitude = sqrtf(horizontalMagnitude);
            ((GameObject*)child)->anim.velocityX = ((GameObject*)child)->anim.velocityX / horizontalMagnitude;
            ((GameObject*)child)->anim.velocityZ = ((GameObject*)child)->anim.velocityZ / horizontalMagnitude;
        }
        ((GameObject*)child)->anim.velocityX =
            ((GameObject*)child)->anim.velocityX *
            -(0.01f * (f32)randomGetRange(0, LARGECRATE_CHILD_RANDOM_VELOCITY_MAX) - 1.0f);
        ((GameObject*)child)->anim.velocityZ =
            ((GameObject*)child)->anim.velocityZ *
            (1.0f - 0.01f * (f32)randomGetRange(0, LARGECRATE_CHILD_RANDOM_VELOCITY_MAX));
        ((GameObject*)child)->anim.velocityY = 2.2f;
        rotation.posX = 0.0f;
        rotation.posY = 0.0f;
        rotation.posZ = 0.0f;
        rotation.scale = 1.0f;
        rotation.rotZ = 0;
        rotation.rotY = 0;
        rotation.rotX = randomGetRange(-10000, 10000);
        vecRotateZXY(&rotation.rotX, (f32*)(child + 0x24));
        angleDelta =
            *(s16*)child -
            ((int)(s16)getAngle(((GameObject*)child)->anim.velocityX, -((GameObject*)child)->anim.velocityZ) & 0xFFFF);
        if (angleDelta > LARGECRATE_YAW_HALF_TURN) {
            angleDelta = angleDelta - LARGECRATE_YAW_WRAP;
        }
        if (angleDelta < -LARGECRATE_YAW_HALF_TURN) {
            angleDelta = angleDelta + LARGECRATE_YAW_WRAP;
        }
        *(s16*)child = angleDelta;
        break;
    case LARGECRATE_DROPTYPE_RED_SCARAB:
        childPlacement = (char*)Obj_AllocObjectSetup(SCARAB_PLACEMENT_SIZE, SCARAB_OBJECT_RED);
        ((ScarabPlacement*)childPlacement)->yawByte = randomGetRange(-0x7F, 0x7E);
        ((ScarabPlacement*)childPlacement)->base.posX = obj->anim.localPosX;
        ((ScarabPlacement*)childPlacement)->base.posY = obj->anim.localPosY;
        ((ScarabPlacement*)childPlacement)->base.posZ = obj->anim.localPosZ;
        ((ScarabPlacement*)childPlacement)->activeTimer = 400;
        child = (char*)Obj_SetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1,
                                       (void*)*(int*)&obj->anim.parent);
        ((GameObject*)child)->anim.velocityX = obj->anim.localPosX - playerRef->anim.localPosX;
        ((GameObject*)child)->anim.velocityZ = obj->anim.localPosZ - playerRef->anim.localPosZ;
        horizontalMagnitude = ((GameObject*)child)->anim.velocityX * ((GameObject*)child)->anim.velocityX +
                              ((GameObject*)child)->anim.velocityZ * ((GameObject*)child)->anim.velocityZ;
        if (horizontalMagnitude != zero) {
            horizontalMagnitude = sqrtf(horizontalMagnitude);
            ((GameObject*)child)->anim.velocityX = ((GameObject*)child)->anim.velocityX / horizontalMagnitude;
            ((GameObject*)child)->anim.velocityZ = ((GameObject*)child)->anim.velocityZ / horizontalMagnitude;
        }
        ((GameObject*)child)->anim.velocityX =
            ((GameObject*)child)->anim.velocityX *
            -(0.01f * (f32)randomGetRange(0, LARGECRATE_CHILD_RANDOM_VELOCITY_MAX) - 1.0f);
        ((GameObject*)child)->anim.velocityZ =
            ((GameObject*)child)->anim.velocityZ *
            (1.0f - 0.01f * (f32)randomGetRange(0, LARGECRATE_CHILD_RANDOM_VELOCITY_MAX));
        ((GameObject*)child)->anim.velocityY = 2.2f;
        rotation.posX = 0.0f;
        rotation.posY = 0.0f;
        rotation.posZ = 0.0f;
        rotation.scale = 1.0f;
        rotation.rotZ = 0;
        rotation.rotY = 0;
        rotation.rotX = randomGetRange(-10000, 10000);
        vecRotateZXY(&rotation.rotX, (f32*)(child + 0x24));
        angleDelta =
            *(s16*)child -
            ((int)(s16)getAngle(((GameObject*)child)->anim.velocityX, -((GameObject*)child)->anim.velocityZ) & 0xFFFF);
        if (angleDelta > LARGECRATE_YAW_HALF_TURN) {
            angleDelta = angleDelta - LARGECRATE_YAW_WRAP;
        }
        if (angleDelta < -LARGECRATE_YAW_HALF_TURN) {
            angleDelta = angleDelta + LARGECRATE_YAW_WRAP;
        }
        *(s16*)child = angleDelta;
        break;
    case LARGECRATE_DROPTYPE_GOLD_SCARAB:
        childPlacement = (char*)Obj_AllocObjectSetup(SCARAB_PLACEMENT_SIZE, SCARAB_OBJECT_GOLD);
        ((ScarabPlacement*)childPlacement)->yawByte = randomGetRange(-0x7F, 0x7E);
        ((ScarabPlacement*)childPlacement)->base.posX = obj->anim.localPosX;
        ((ScarabPlacement*)childPlacement)->base.posY = obj->anim.localPosY;
        ((ScarabPlacement*)childPlacement)->base.posZ = obj->anim.localPosZ;
        ((ScarabPlacement*)childPlacement)->activeTimer = 2000;
        child = (char*)Obj_SetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1,
                                       (void*)*(int*)&obj->anim.parent);
        ((GameObject*)child)->anim.velocityX = obj->anim.localPosX - playerRef->anim.localPosX;
        ((GameObject*)child)->anim.velocityZ = obj->anim.localPosZ - playerRef->anim.localPosZ;
        horizontalMagnitude = ((GameObject*)child)->anim.velocityX * ((GameObject*)child)->anim.velocityX +
                              ((GameObject*)child)->anim.velocityZ * ((GameObject*)child)->anim.velocityZ;
        if (horizontalMagnitude != zero) {
            horizontalMagnitude = sqrtf(horizontalMagnitude);
            ((GameObject*)child)->anim.velocityX = ((GameObject*)child)->anim.velocityX / horizontalMagnitude;
            ((GameObject*)child)->anim.velocityZ = ((GameObject*)child)->anim.velocityZ / horizontalMagnitude;
        }
        ((GameObject*)child)->anim.velocityX =
            ((GameObject*)child)->anim.velocityX *
            -(0.01f * (f32)randomGetRange(0, LARGECRATE_CHILD_RANDOM_VELOCITY_MAX) - 1.0f);
        ((GameObject*)child)->anim.velocityZ =
            ((GameObject*)child)->anim.velocityZ *
            (1.0f - 0.01f * (f32)randomGetRange(0, LARGECRATE_CHILD_RANDOM_VELOCITY_MAX));
        ((GameObject*)child)->anim.velocityY = 2.2f;
        rotation.posX = 0.0f;
        rotation.posY = 0.0f;
        rotation.posZ = 0.0f;
        rotation.scale = 1.0f;
        rotation.rotZ = 0;
        rotation.rotY = 0;
        rotation.rotX = randomGetRange(-10000, 10000);
        vecRotateZXY(&rotation.rotX, (f32*)(child + 0x24));
        angleDelta =
            *(s16*)child -
            ((int)(s16)getAngle(((GameObject*)child)->anim.velocityX, -((GameObject*)child)->anim.velocityZ) & 0xFFFF);
        if (angleDelta > LARGECRATE_YAW_HALF_TURN) {
            angleDelta = angleDelta - LARGECRATE_YAW_WRAP;
        }
        if (angleDelta < -LARGECRATE_YAW_HALF_TURN) {
            angleDelta = angleDelta + LARGECRATE_YAW_WRAP;
        }
        *(s16*)child = angleDelta;
        break;
    case LARGECRATE_DROPTYPE_ENERGY_EGG:
    case LARGECRATE_DROPTYPE_APPLE:
        if (state->dropType == LARGECRATE_DROPTYPE_ENERGY_EGG) {
            childPlacement = (char*)Obj_AllocObjectSetup(0x30, LARGECRATE_CHILD_OBJECT_ENERGY_EGG);
        } else {
            childPlacement = (char*)Obj_AllocObjectSetup(0x30, LARGECRATE_CHILD_OBJECT_APPLE);
        }
        ((CollectibleSetup*)childPlacement)->unk1A = 0x14;
        ((CollectibleSetup*)childPlacement)->counterGameBit = -1;
        ((CollectibleSetup*)childPlacement)->hideGameBit = -1;
        ((CollectibleSetup*)childPlacement)->base.posX = obj->anim.localPosX;
        ((CollectibleSetup*)childPlacement)->base.posY = 5.0f + obj->anim.localPosY;
        ((CollectibleSetup*)childPlacement)->base.posZ = obj->anim.localPosZ;
        ((CollectibleSetup*)childPlacement)->visibilityGameBit = -1;
        child = (char*)Obj_SetupObject((ObjPlacement*)childPlacement, 5, obj->anim.mapEventSlot, -1,
                                       (void*)*(int*)&obj->anim.parent);
        (*(CollectibleInterface**)((GameObject*)child)->anim.dll)
            ->startBounceMotion((GameObject*)child, 0.0f, 1.0f, 0.0f);
        break;
    case LARGECRATE_DROPTYPE_NONE_A:
    case LARGECRATE_DROPTYPE_NONE_B:
        mainSetBits(state->brokenGameBit, 1);
        break;
    case LARGECRATE_DROPTYPE_PICKUP:
        LargeCrate_spawnPickup(obj);
        break;
    }
    return 0;
}

int LargeCrate_seq(GameObject* obj) {
    if (obj->seqIndex != -1) {
        (*gCameraInterface)->setTargetReticleOverride((int)obj);
    }
    return 0;
}

int LargeCrate_getExtraSize(void) {
    return sizeof(LargeCrateState);
}

int LargeCrate_getObjectTypeId(void) {
    return 0;
}

void LargeCrate_free(GameObject* obj) {
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(gLargeCrateResource);
}

void LargeCrate_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    LargeCrateState* state;
    LargeCratePlacement* placement;
    s16 breakTimer;

    state = obj->extra;
    placement = (LargeCratePlacement*)obj->anim.placementData;
    if (((*gMapEventInterface)->shouldNotSaveTime(placement->base.mapId) == 0) ||
        (((breakTimer = state->breakTimer) != 0) && (breakTimer <= LARGECRATE_BREAK_FRAMES)) ||
        (state->hiddenTimer > 0.0f)) {
        obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
    } else {
        if (obj->userData2 != 0) {
            if (visible != -1) {
                obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
                return;
            }
        } else if (visible == 0) {
            obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
            return;
        }
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void LargeCrate_hitDetect(GameObject* obj) {
}

void LargeCrate_update(GameObject* obj) {
    GameObject* player;
    LargeCratePlacement* placement;
    LargeCrateState* state;
    PartFxSpawnParams effectParams;
    u8 hitInfo[4];
    int hitType;
    int hitDamage;
    f32 clockScale;
    int hitKind;
    int alpha;
    f32 zero;

    placement = (LargeCratePlacement*)obj->anim.placementData;
    hitType = -1;
    clockScale = 1.0f;
    (*gSkyInterface)->getClockTime(&clockScale);
    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (obj->anim.parent != NULL) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    if ((*gMapEventInterface)->shouldNotSaveTime(placement->base.mapId) == 0) {
        ObjHits_DisableObject(obj);
    } else {
        if (state->hiddenTimer > (zero = 0.0f)) {
            obj->anim.alpha = 0;
            if (state->respawnDelay != -1) {
                state->hiddenTimer = -(timeDelta * clockScale - state->hiddenTimer);
                if (state->hiddenTimer <= zero) {
                    if (!LargeCrate_isPlayerFar(obj)) {
                        state->hiddenTimer = 1.0f;
                    } else {
                        state->hiddenTimer = 0.0f;
                        state->breakTimer = 0;
                        ObjHits_EnableObject(obj);
                        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                    }
                }
            }
        } else {
            alpha = (int)(LARGECRATE_FADE_STEP * timeDelta + (f32)(u32)obj->anim.alpha);
            if (alpha > LARGECRATE_ALPHA_MAX) {
                alpha = LARGECRATE_ALPHA_MAX;
            }
            obj->anim.alpha = alpha;
            if (state->breakTimer != 0) {
                ObjHits_DisableObject(obj);
                if ((state->breakTimer -= framesThisStep) <= 0) {
                    if (state->respawnDelay > 0) {
                        state->hiddenTimer = 1.0f;
                        (*gMapEventInterface)->addTime(placement->base.mapId, (f32)state->respawnDelay);
                    } else {
                        state->hiddenTimer = 1.0f;
                    }
                    obj->anim.localPosX = placement->base.posX;
                    obj->anim.localPosY = placement->base.posY;
                    obj->anim.localPosZ = placement->base.posZ;
                    obj->anim.previousLocalPosX = placement->base.posX;
                    obj->anim.previousLocalPosY = placement->base.posY;
                    obj->anim.previousLocalPosZ = placement->base.posZ;
                    zero = 0.0f;
                    obj->anim.velocityX = zero;
                    obj->anim.velocityY = zero;
                    obj->anim.velocityZ = zero;
                }
                if (state->breakTimer <= LARGECRATE_BREAK_FRAMES) {
                    return;
                }
            }
            obj->anim.rotY = state->spinSpeed;
            state->spinSpeed *= -0.5f;
            if ((obj->anim.rotY < 10) && (-10 < obj->anim.rotY)) {
                obj->anim.rotY = 0;
            }
            hitKind = ObjHits_GetPriorityHitWithPosition(obj, (int*)hitInfo, &hitType, (u32*)&hitDamage,
                                                         &effectParams.posX, &effectParams.posY, &effectParams.posZ);
            if (hitKind == 0x10) {
                Obj_StartModelFadeIn(obj, LARGECRATE_MODEL_FADE_FRAMES);
                hitKind = 0;
            }
            if ((hitKind != 0) && (obj->anim.parent == NULL)) {
                state->damageTaken = state->damageTaken + hitDamage;
                Obj_SetModelColorFadeRecursive(obj, 0xF, 200, 0, 0, 1);
                effectParams.posX = effectParams.posX + playerMapOffsetX;
                effectParams.posZ = effectParams.posZ + playerMapOffsetZ;
                objLightFn_8009a1dc((void*)obj, LARGECRATE_EFFECT_SCALE, &effectParams, 1, 0);
                if (state->damageTaken < state->damageThreshold) {
                    if (Sfx_IsPlayingFromObject(0, (u16)state->hitSfxId) == 0) {
                        Sfx_PlayFromObject((int)obj, (u16)state->hitSfxId);
                    }
                    if (obj->anim.seqId == LARGECRATE_SEQUENCE_VARIANT_A) {
                        state->spinSpeed = randomGetRange(LARGECRATE_SPIN_SPEED_MIN, LARGECRATE_SPIN_SPEED_MAX);
                    }
                } else {
                    Sfx_StopObjectChannel((int)obj, 0x7F);
                    (*gLargeCrateResource)->spawnBreakEffect(obj, 1, 0, 2, -1, 0);
                    if (Sfx_IsPlayingFromObject(0, (u16)state->breakSfxId) == 0) {
                        Sfx_PlayFromObject((int)obj, (u16)state->breakSfxId);
                    }
                    state->breakTimer = LARGECRATE_BREAK_FRAMES;
                    state->damageTaken = 0;
                    LargeCrate_spawnDropContents(obj, player, state);
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                }
            }
            vec3f_distanceSquared(&Obj_GetPlayerObject()->anim.worldPosX, &obj->anim.worldPosX);
            if ((state->idleTimer -= framesThisStep) <= 0) {
                state->idleTimer = (s16)(randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_DELAY_MAX) +
                                         LARGECRATE_RANDOM_DELAY_BASE);
            }
            if (obj->anim.parent != NULL) {
                LargeCrate_updateConveyorSlide(obj, state);
            }
        }
    }
}

void LargeCrate_init(GameObject* obj, LargeCratePlacement* placement) {
    LargeCrateState* state;
    u32 randomValue;
    f32 slidePhase;
    LargeCrateVariantRemap variantARemap;
    LargeCrateVariantRemap variantBRemap;
    s16 value;

    variantARemap = gLargeCrateVariantARemap;
    variantBRemap = gLargeCrateVariantBRemap;

    state = obj->extra;
    obj->animEventCallback = LargeCrate_seq;
    obj->anim.rotX = (s16)((int)placement->rotXByte << 8);
    state->brokenGameBit = placement->brokenGameBit;

    value = placement->respawnMinutes;
    if (value == LARGECRATE_RESPAWN_DISABLED) {
        state->respawnDelay = LARGECRATE_RESPAWN_DISABLED;
    } else if (value == LARGECRATE_RESPAWN_PERMANENT) {
        state->respawnDelay = -1;
    } else {
        state->respawnDelay = value * LARGECRATE_RESPAWN_FRAMES_PER_MINUTE;
    }

    if (mainGetBit((int)state->brokenGameBit) != 0) {
        state->hiddenTimer = 1.0f;
        ObjHits_DisableObject(obj);
    }

    state->dropType = placement->dropType;
    gLargeCrateResource = Resource_Acquire(LARGECRATE_RESOURCE_ID, LARGECRATE_RESOURCE_COUNT);
    randomValue = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_DELAY_MAX);
    state->idleTimer = (s16)(randomValue + LARGECRATE_RANDOM_DELAY_BASE);
    state->unk0C = LARGECRATE_UNK_0C_INITIAL;
    state->unk12 = (u8)placement->unk1A;
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->anim.rotX = (s16)((int)placement->rotXByte << 8);

    value = obj->anim.seqId;
    if (value == LARGECRATE_SEQUENCE_VARIANT_A) {
        state->dropType = variantARemap.entries[state->dropType];
        state->hitSfxId = LARGECRATE_VARIANT_A_HIT_SFX;
        state->breakSfxId = LARGECRATE_VARIANT_A_BREAK_SFX;
    } else if (value == LARGECRATE_SEQUENCE_VARIANT_B || value == LARGECRATE_SEQUENCE_VARIANT_C) {
        state->dropType = variantBRemap.entries[state->dropType];
        state->hitSfxId = LARGECRATE_VARIANT_B_HIT_SFX;
        state->breakSfxId = LARGECRATE_VARIANT_B_BREAK_SFX;
    }

    state->slideOffset = 0;
    randomValue = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_SLIDE_PHASE_MAX);
    slidePhase = (f32)(int)randomValue;
    slidePhase = 1500.0f + slidePhase;
    state->slidePhase = slidePhase;
    state->homeX = obj->anim.localPosX;

    if (obj->anim.seqId == LARGECRATE_SEQUENCE_VARIANT_C) {
        state->damageThreshold = 0;
    } else {
        state->damageThreshold = 2;
    }
}

void LargeCrate_release(void) {
}

void LargeCrate_initialise(void) {
}
