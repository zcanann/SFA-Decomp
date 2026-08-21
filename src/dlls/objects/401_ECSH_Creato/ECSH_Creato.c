/*
 * ECSH_Creato (DLL 0x191) - ECSH shrine SharpClaw encounter spawner.
 *
 * A game bit triggers its activation effects and starts a countdown. Once the
 * countdown expires, the creator spawns object ID 0x11, which retail
 * OBJINDEX.bin maps to "sharpclawGr" (DLL 0xC9).
 */
#include "dlls/objects/401_ECSH_Creato.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/baddie_placement.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_0082_modgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mm.h"
#include "main/object_render.h"
#include "main/resource.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define ECSH_CREATOR_EFFECT_RESOURCE_ID  0x82
#define ECSH_CREATOR_SHARPCLAW_OBJECT_ID 0x11

#define ECSH_CREATOR_SPAWN_TIMER               100
#define ECSH_CREATOR_SHARPCLAW_HIT_POINTS_BASE 2

#define ECSH_CREATOR_SHARPCLAW_INITIAL_WEAPON_ID       3
#define ECSH_CREATOR_SHARPCLAW_FLAGS                   2
#define ECSH_CREATOR_SHARPCLAW_DISABLE_CAMERA_TARGET   0x20
#define ECSH_CREATOR_SHARPCLAW_AGGRO_RANGE_BYTE        0xFF
#define ECSH_CREATOR_SHARPCLAW_INVALID_DROPPED_ITEM_ID -1
#define ECSH_CREATOR_SHARPCLAW_NO_TRIGGER_SEQUENCE     -1

#define ECSH_CREATOR_SETUP_ALLOC_TYPE  0xE
#define ECSH_CREATOR_SETUP_ALLOC_FLAGS 0
#define ECSH_CREATOR_CHILD_SETUP_FLAGS 5
#define ECSH_CREATOR_NO_MAP_ID         -1
#define ECSH_CREATOR_NO_OBJECT_INDEX   -1

#define ECSH_CREATOR_INITIAL_YAW_SHIFT 8
#define ECSH_CREATOR_FULL_ALPHA        0xFF

int ecshCreator_getExtraSize(void) {
    return sizeof(ECSHCreatorState);
}

int ecshCreator_getObjectTypeId(void) {
    return 0;
}

void ecshCreator_free(void) {
}

void ecshCreator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible;

    isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void ecshCreator_hitDetect(void) {
}

void ecshCreator_update(GameObject* obj) {
    const ECSHCreatorPlacement* placement;
    ECSHCreatorState* state;
    Dll82Interface** effectResource;
    EnemyPlacement* spawnSetup;
    GameObject* sharpClaw;

    placement = (const ECSHCreatorPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (obj->userData2 == 0 && mainGetBit(state->triggerGameBit) != 0) {
        effectResource = Resource_Acquire(ECSH_CREATOR_EFFECT_RESOURCE_ID, 1);
        (*effectResource)->spawn(obj, 0, NULL, 1, -1, NULL);
        (*effectResource)->spawn(obj, 1, NULL, 1, -1, NULL);
        Sfx_PlayFromObject(obj, SFXTRIG_wp_hitpos_6);
        Resource_Release(effectResource);
        state->spawnTimerRate = 1;
        obj->userData2 = 1;
    }
    if (state->spawnTimerRate != 0) {
        state->spawnTimer -= state->spawnTimerRate * framesThisStep;
    }
    if (Obj_CanSetupObject() != 0 && state->spawnTimer <= 0) {
        spawnSetup = mmAlloc(sizeof(EnemyPlacement), ECSH_CREATOR_SETUP_ALLOC_TYPE, ECSH_CREATOR_SETUP_ALLOC_FLAGS);
        spawnSetup->base.posX = placement->base.posX;
        spawnSetup->base.posY = placement->base.posY;
        spawnSetup->base.posZ = placement->base.posZ;
        spawnSetup->base.objectId = ECSH_CREATOR_SHARPCLAW_OBJECT_ID;
        spawnSetup->base.ident = ECSH_CREATOR_NO_MAP_ID;
        spawnSetup->base.color[0] = placement->base.color[0];
        spawnSetup->base.color[1] = placement->base.color[1];
        spawnSetup->base.color[2] = placement->base.color[2];
        spawnSetup->base.color[3] = placement->base.color[3];
        spawnSetup->initialWeaponId = ECSH_CREATOR_SHARPCLAW_INITIAL_WEAPON_ID;
        spawnSetup->objectFlagBits = 0;
        spawnSetup->gameBit = state->triggerGameBit + placement->childGameBitOffset;
        spawnSetup->unk30 = -1;
        spawnSetup->initialYaw = (s8)(obj->anim.rotX >> ECSH_CREATOR_INITIAL_YAW_SHIFT);
        spawnSetup->flags = ECSH_CREATOR_SHARPCLAW_FLAGS;
        spawnSetup->unk20 = 0;
        spawnSetup->unk1E = 0;
        spawnSetup->droppedItemId = ECSH_CREATOR_SHARPCLAW_INVALID_DROPPED_ITEM_ID;
        spawnSetup->aggroRangeByte = ECSH_CREATOR_SHARPCLAW_AGGRO_RANGE_BYTE;
        spawnSetup->triggerSequenceId = ECSH_CREATOR_SHARPCLAW_NO_TRIGGER_SEQUENCE;
        spawnSetup->unk24 = 0;
        spawnSetup->respawnDelay = 0;
        spawnSetup->unk34 = 0xFFFF;
        spawnSetup->gameBit2 = 0;
        spawnSetup->hitPoints = state->sharpClawHitPoints;
        sharpClaw = objSetupObject(&spawnSetup->base, ECSH_CREATOR_CHILD_SETUP_FLAGS, obj->anim.mapEventSlot,
                                    ECSH_CREATOR_NO_OBJECT_INDEX, obj->anim.parent);
        if (sharpClaw != NULL) {
            ((GroundBaddieState*)sharpClaw->extra)->configFlags = ECSH_CREATOR_SHARPCLAW_DISABLE_CAMERA_TARGET;
        }
        state->spawnTimer = ECSH_CREATOR_SPAWN_TIMER;
        state->spawnTimerRate = 0;
    }
}

void ecshCreator_init(GameObject* obj, const ECSHCreatorPlacement* placement) {
    ECSHCreatorState* state = obj->extra;

    obj->anim.rotX = (s16)((s32)placement->initialYaw << ECSH_CREATOR_INITIAL_YAW_SHIFT);
    obj->userData2 = 0;
    state->spawnTimer = ECSH_CREATOR_SPAWN_TIMER;
    state->spawnTimerRate = 0;
    obj->anim.renderAlpha = ECSH_CREATOR_FULL_ALPHA;
    obj->anim.alpha = ECSH_CREATOR_FULL_ALPHA;
    state->triggerGameBit = placement->triggerGameBit;
    state->sharpClawHitPoints = ECSH_CREATOR_SHARPCLAW_HIT_POINTS_BASE;
    state->sharpClawHitPoints += placement->hitPointsOffset;
}

void ecshCreator_release(void) {
}

void ecshCreator_initialise(void) {
}

ObjectDescriptor gECSHCreatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ecshCreator_initialise,
    (ObjectDescriptorCallback)ecshCreator_release,
    0,
    (ObjectDescriptorCallback)ecshCreator_init,
    (ObjectDescriptorCallback)ecshCreator_update,
    (ObjectDescriptorCallback)ecshCreator_hitDetect,
    (ObjectDescriptorCallback)ecshCreator_render,
    (ObjectDescriptorCallback)ecshCreator_free,
    (ObjectDescriptorCallback)ecshCreator_getObjectTypeId,
    ecshCreator_getExtraSize,
};
