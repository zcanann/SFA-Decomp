/*
 * GPSH_ObjCre (DLL 0x193) - Test of Knowledge symbol creator.
 *
 * The shrine activates six indexed child types. Each creator counts down,
 * emits a hit effect, and spawns its configured child at the creator's
 * position. The shrine reset bit re-arms the creator for another attempt.
 */
#include "dlls/objects/403_GPSH_ObjCre.h"

#include "dlls/objects/402_GPSH_Shrine.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

typedef struct GPSHObjCreatorChildSetup {
    ObjPlacement base;
    u8 yawByte;
    u8 unknown19;
    s16 unknown1A;
    u8 unknown1C[0x24 - 0x1C];
} GPSHObjCreatorChildSetup;

STATIC_ASSERT(sizeof(GPSHObjCreatorChildSetup) == 0x24);
STATIC_ASSERT(offsetof(GPSHObjCreatorChildSetup, base) == 0x00);
STATIC_ASSERT(offsetof(GPSHObjCreatorChildSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(GPSHObjCreatorChildSetup, unknown19) == 0x19);
STATIC_ASSERT(offsetof(GPSHObjCreatorChildSetup, unknown1A) == 0x1A);
STATIC_ASSERT(offsetof(GPSHObjCreatorChildSetup, unknown1C) == 0x1C);

#define GPSH_OBJ_CREATOR_OBJECT_TYPE_ID       0
#define GPSH_OBJ_CREATOR_CHILD_TYPE_COUNT     6
#define GPSH_OBJ_CREATOR_CHILD_OBJECT_ID_BASE 0x1F4
#define GPSH_OBJ_CREATOR_SPAWN_DELAY          100.0f
#define GPSH_OBJ_CREATOR_HIT_EFFECT_SCALE     0.6f
#define GPSH_OBJ_CREATOR_HIT_EFFECT_ID        2
#define GPSH_OBJ_CREATOR_HIT_EFFECT_VARIANT   1
#define GPSH_OBJ_CREATOR_HIT_EFFECT_COUNT     1
#define GPSH_OBJ_CREATOR_CHILD_COLOR_RED      0x20
#define GPSH_OBJ_CREATOR_CHILD_COLOR_GREEN    2
#define GPSH_OBJ_CREATOR_FULL_ALPHA           0xFF
#define GPSH_OBJ_CREATOR_YAW_SHIFT            8
#define GPSH_OBJ_CREATOR_CHILD_SETUP_FLAGS    5
#define GPSH_OBJ_CREATOR_NO_OBJECT_INDEX      -1
#define GPSH_OBJ_CREATOR_SFX_SOURCE           0
#define GPSH_OBJ_CREATOR_SFX_LIMIT            1

s16 gGPSHObjCreatorChildParam1AValues[GPSH_OBJ_CREATOR_CHILD_TYPE_COUNT] = {
    0x28, 0x28, 0x30, 0x30, 0x2D, 0x2D,
};

int gpshObjCreator_getExtraSize(void) {
    return sizeof(GPSHObjCreatorState);
}

int gpshObjCreator_getObjectTypeId(void) {
    return GPSH_OBJ_CREATOR_OBJECT_TYPE_ID;
}

void gpshObjCreator_free(void) {
}

void gpshObjCreator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void gpshObjCreator_hitDetect(void) {
}

void gpshObjCreator_update(GameObject* obj) {
    GPSHObjCreatorState* state;
    GPSHObjCreatorChildSetup* childSetup;

    state = obj->extra;
    if (mainGetBit(GAMEBIT_GPSH_ResetSymbolCreators) != 0) {
        obj->userData2 = 0;
        state->flags.childSpawned = 0;
        obj->anim.renderAlpha = GPSH_OBJ_CREATOR_FULL_ALPHA;
        obj->anim.alpha = GPSH_OBJ_CREATOR_FULL_ALPHA;
    }
    if (state->flags.childSpawned != 0) {
        return;
    }
    if (obj->userData2 == 0) {
        if (mainGetBit(GAMEBIT_GPSH_SpawnKnowledgeSymbols) != 0) {
            state->spawnTimer = GPSH_OBJ_CREATOR_SPAWN_DELAY;
            obj->userData2 = 1;
        }
    }
    if (Obj_IsLoadingLocked() == 0) {
        return;
    }
    if (!state->spawnTimer) {
        return;
    }

    state->spawnTimer -= timeDelta;
    objfx_spawnHitEffectBurst(obj, GPSH_OBJ_CREATOR_HIT_EFFECT_SCALE, GPSH_OBJ_CREATOR_HIT_EFFECT_ID,
                              GPSH_OBJ_CREATOR_HIT_EFFECT_VARIANT, GPSH_OBJ_CREATOR_HIT_EFFECT_COUNT, NULL);
    if (state->spawnTimer <= 0.0f) {
        Sfx_PlayFromObjectLimited(GPSH_OBJ_CREATOR_SFX_SOURCE, SFXTRIG_wp_hitpos_6_167, GPSH_OBJ_CREATOR_SFX_LIMIT);
        childSetup = (GPSHObjCreatorChildSetup*)Obj_AllocObjectSetup(
            sizeof(GPSHObjCreatorChildSetup), state->childTypeIndex + GPSH_OBJ_CREATOR_CHILD_OBJECT_ID_BASE);
        state->flags.childSpawned = 1;
        childSetup->base.color[3] = GPSH_OBJ_CREATOR_FULL_ALPHA;
        childSetup->base.color[0] = GPSH_OBJ_CREATOR_CHILD_COLOR_RED;
        childSetup->base.color[1] = GPSH_OBJ_CREATOR_CHILD_COLOR_GREEN;
        childSetup->base.posX = obj->anim.localPosX;
        childSetup->base.posY = obj->anim.localPosY;
        childSetup->base.posZ = obj->anim.localPosZ;
        childSetup->base.objectId = (s16)(state->childTypeIndex + GPSH_OBJ_CREATOR_CHILD_OBJECT_ID_BASE);
        childSetup->yawByte = (u8)(obj->anim.rotX >> GPSH_OBJ_CREATOR_YAW_SHIFT);
        childSetup->unknown1A = gGPSHObjCreatorChildParam1AValues[state->childTypeIndex];
        objSetupObject(&childSetup->base, GPSH_OBJ_CREATOR_CHILD_SETUP_FLAGS, obj->anim.mapEventSlot,
                       GPSH_OBJ_CREATOR_NO_OBJECT_INDEX, obj->anim.parent);
    }
}

void gpshObjCreator_init(GameObject* obj, const GPSHObjCreatorPlacement* placement) {
    GPSHObjCreatorState* state;

    state = obj->extra;
    obj->anim.rotX = (s16)(placement->initialYaw << GPSH_OBJ_CREATOR_YAW_SHIFT);
    obj->userData2 = 0;
    state->childTypeIndex = (u8)placement->childTypeIndex;
    state->flags.childSpawned = 0;
    obj->anim.renderAlpha = GPSH_OBJ_CREATOR_FULL_ALPHA;
    obj->anim.alpha = GPSH_OBJ_CREATOR_FULL_ALPHA;
}

void gpshObjCreator_release(void) {
}

void gpshObjCreator_initialise(void) {
}

ObjectDescriptor10WithPadding gGPSHObjCreatorObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)gpshObjCreator_initialise,
        (ObjectDescriptorCallback)gpshObjCreator_release,
        0,
        (ObjectDescriptorCallback)gpshObjCreator_init,
        (ObjectDescriptorCallback)gpshObjCreator_update,
        (ObjectDescriptorCallback)gpshObjCreator_hitDetect,
        (ObjectDescriptorCallback)gpshObjCreator_render,
        (ObjectDescriptorCallback)gpshObjCreator_free,
        (ObjectDescriptorCallback)gpshObjCreator_getObjectTypeId,
        gpshObjCreator_getExtraSize,
    },
    0,
};
