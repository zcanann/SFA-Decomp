/*
 * Treasure-chest interactive object (DLL slot 285 / 0x11D).
 *
 * Activating a closed chest runs its object sequence and records the opened
 * game bit. Sequence events show dialogue, control the hit effect, and hide
 * the chest once its opening animation has completed.
 */
#include "dlls/objects/285.h"
#include "dlls/objects/237.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/game_ui_interface.h"
#include "main/objHitReact_types.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/objfx.h"
#include "main/object_render.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "sys/objects.h"
#include "main/dll/player_staff_api.h"
#include "main/gamebits_api.h"
#include "main/objhits.h"

#define TREASURE_CHEST_OBJECT_TYPE_ID 0
#define TREASURE_CHEST_GAME_BIT_NONE  -1

#define TREASURE_CHEST_SEQUENCE_EVENT_DIALOGUE           1
#define TREASURE_CHEST_SEQUENCE_EVENT_ENABLE_HIT_EFFECT  2
#define TREASURE_CHEST_SEQUENCE_EVENT_DISABLE_HIT_EFFECT 3
#define TREASURE_CHEST_SEQUENCE_EVENT_OPENED             4

#define TREASURE_CHEST_HIT_EFFECT_SCALE        0.6f
#define TREASURE_CHEST_HIT_EFFECT_TYPE         2
#define TREASURE_CHEST_HITBOX_KIND_OFFSET      6
#define TREASURE_CHEST_HIT_EFFECT_BURST_COUNT  4
#define TREASURE_CHEST_HIT_EFFECT_COOLDOWN     0x3C
#define TREASURE_CHEST_IGNORED_HIT_TYPE        0xE
#define TREASURE_CHEST_COLLECTIBLE_SEARCH_DIST 20.0f
#define TREASURE_CHEST_HIT_SPHERE_INDEX_NONE   0xFFFFFFFF

#define TREASURE_CHEST_OPEN_MOVE_ID       0
#define TREASURE_CHEST_OPEN_MOVE_PROGRESS 0.99f
#define TREASURE_CHEST_OPEN_MOVE_FLAGS    0

#define TREASURE_CHEST_DEFAULT_SEQUENCE     0
#define TREASURE_CHEST_COLLECTIBLE_SEQUENCE 1
#define TREASURE_CHEST_SEQUENCE_ARG_NONE    0xFFFFFFFF
#define TREASURE_CHEST_STAFF_MODE           1

int gTreasureChestHitEffectCooldown;
const StaffCollisionColorArgs gTreasureChestHitEffectColors = {8, 0xFF, 0xFF, 0x78};
StaffCollisionInterface** gTreasureChestStaffCollisionInterface;

int TreasureChest_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int eventIndex;
    TreasureChestPlacement* placement;
    TreasureChestObjectState* state;
    u8 eventId;

    placement = (TreasureChestPlacement*)obj->anim.placementData;
    state = obj->extra;
    eventIndex = 0;
    while (eventIndex < animUpdate->eventCount) {
        eventId = animUpdate->eventIds[eventIndex];
        switch (eventId) {
        case TREASURE_CHEST_SEQUENCE_EVENT_DIALOGUE:
            if (placement->dialogueId != 0) {
                (*gGameUIInterface)->showNpcDialogue(placement->dialogueId, 0xC8, 0x8C, 0);
            }
            break;
        case TREASURE_CHEST_SEQUENCE_EVENT_ENABLE_HIT_EFFECT:
            state->hitEffectEnabled = 1;
            break;
        case TREASURE_CHEST_SEQUENCE_EVENT_DISABLE_HIT_EFFECT:
            state->hitEffectEnabled = 0;
            break;
        case TREASURE_CHEST_SEQUENCE_EVENT_OPENED:
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
            break;
        }
        eventIndex++;
    }
    return 0;
}

int TreasureChest_getExtraSize(void) {
    return sizeof(TreasureChestObjectState);
}

int TreasureChest_getObjectTypeId(void) {
    return TREASURE_CHEST_OBJECT_TYPE_ID;
}

void TreasureChest_free(void) {
    Resource_Release(gTreasureChestStaffCollisionInterface);
}

void TreasureChest_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void TreasureChest_hitDetect(GameObject* obj) {
    TreasureChestObjectState* state;
    TreasureChestPlacement* placement;

    placement = (TreasureChestPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (state->hitEffectEnabled != 0) {
        objfx_spawnHitEffectBurst(obj, TREASURE_CHEST_HIT_EFFECT_SCALE, TREASURE_CHEST_HIT_EFFECT_TYPE,
                                  (placement->hitboxKind + TREASURE_CHEST_HITBOX_KIND_OFFSET),
                                  TREASURE_CHEST_HIT_EFFECT_BURST_COUNT, NULL);
    }
}

void TreasureChest_update(GameObject* obj) {
    TreasureChestObjectState* state;
    TreasureChestPlacement* placement;
    GameObject* nearestCollectible;
    int hitType;
    PartFxSpawnParams spawnParams;
    StaffCollisionColorArgs hitEffectColors;
    f32 nearestDist;
    u32 hitVolume;
    int hitSphereIndex;
    GameObject* hitObject;

    state = obj->extra;
    placement = (TreasureChestPlacement*)obj->anim.placementData;
    nearestDist = TREASURE_CHEST_COLLECTIBLE_SEARCH_DIST;
    if (state->restoreOpenState != 0 && state->opened != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        ObjAnim_SetCurrentMove(obj, TREASURE_CHEST_OPEN_MOVE_ID, TREASURE_CHEST_OPEN_MOVE_PROGRESS,
                               TREASURE_CHEST_OPEN_MOVE_FLAGS);
    }
    if (state->opened == 0) {
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            playerPullOutStaff(Obj_GetPlayerObject(), TREASURE_CHEST_STAFF_MODE);
            nearestCollectible = objGetNearestTypeTo(COLLECTIBLE_OBJECT_GROUP, obj, &nearestDist);
            if (nearestCollectible != 0) {
                (*gObjectTriggerInterface)->setObjects((int)nearestCollectible->anim.romDefNo, NULL, 0);
                (*gObjectTriggerInterface)
                    ->runSequence(TREASURE_CHEST_COLLECTIBLE_SEQUENCE, obj, TREASURE_CHEST_SEQUENCE_ARG_NONE);
            } else {
                (*gObjectTriggerInterface)->setObjects(placement->triggerObjectId, NULL, 0);
                (*gObjectTriggerInterface)
                    ->runSequence(TREASURE_CHEST_DEFAULT_SEQUENCE, obj, TREASURE_CHEST_SEQUENCE_ARG_NONE);
            }
            mainSetBits(placement->openedGameBit, 1);
            state->opened = 1;
            ObjHits_DisableObject(obj);
        }
        state->restoreOpenState = 0;
        hitEffectColors = gTreasureChestHitEffectColors;
        hitSphereIndex = TREASURE_CHEST_HIT_SPHERE_INDEX_NONE;
        hitType = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume,
                                                     &spawnParams.posX, &spawnParams.posY, &spawnParams.posZ);
        if ((hitType != 0) && (hitType != TREASURE_CHEST_IGNORED_HIT_TYPE)) {
            spawnParams.posX += playerMapOffsetX;
            spawnParams.posZ += playerMapOffsetZ;
            spawnParams.scale = 1.0f;
            spawnParams.rotZ = 0;
            spawnParams.rotY = 0;
            spawnParams.rotX = 0;
            if (gTreasureChestHitEffectCooldown == 0) {
                (*gTreasureChestStaffCollisionInterface)
                    ->spawn(NULL, OBJHITREACT_HIT_EFFECT_MODE, &spawnParams, OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS,
                            OBJHITREACT_HIT_EFFECT_NO_SOURCE, &hitEffectColors);
                gTreasureChestHitEffectCooldown = TREASURE_CHEST_HIT_EFFECT_COOLDOWN;
            }
        }
        if (gTreasureChestHitEffectCooldown != 0) {
            gTreasureChestHitEffectCooldown--;
        }
    }
}

void TreasureChest_init(GameObject* obj) {
    TreasureChestObjectState* state = obj->extra;
    TreasureChestPlacement* placement = (TreasureChestPlacement*)obj->anim.placementData;

    obj->animEventCallback = TreasureChest_SeqFn;
    obj->anim.rotX = (s16)((s32)placement->rotationX << 8);

    if (placement->openedGameBit != TREASURE_CHEST_GAME_BIT_NONE) {
        state->opened = mainGetBit(placement->openedGameBit);
    } else {
        state->opened = 0;
    }
    if (state->opened != 0) {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
    }
    gTreasureChestStaffCollisionInterface =
        Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID, OBJHITREACT_HIT_EFFECT_RESOURCE_COUNT);
    state->restoreOpenState = 1;
}

void TreasureChest_release(void) {
}

void TreasureChest_initialise(void) {
}

ObjectDescriptor gTreasureChestObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)TreasureChest_initialise,
    (ObjectDescriptorCallback)TreasureChest_release,
    0,
    (ObjectDescriptorCallback)TreasureChest_init,
    (ObjectDescriptorCallback)TreasureChest_update,
    (ObjectDescriptorCallback)TreasureChest_hitDetect,
    (ObjectDescriptorCallback)TreasureChest_render,
    (ObjectDescriptorCallback)TreasureChest_free,
    (ObjectDescriptorCallback)TreasureChest_getObjectTypeId,
    TreasureChest_getExtraSize,
};
