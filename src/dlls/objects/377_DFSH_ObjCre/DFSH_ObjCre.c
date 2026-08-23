/*
 * DFSH_ObjCre (DLL 0x179) - shrine SharpClaw encounter spawner.
 *
 * An indexed game bit triggers the activation effects and starts a
 * countdown. Once the countdown expires, this object creates object ID
 * 0x11, which retail OBJINDEX.bin maps to "sharpclawGr" (DLL 0xC9).
 */

#include "dlls/objects/377_DFSH_ObjCre.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/baddie_placement.h"
#include "main/dll/dll_0082_modgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/resource.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define DFSH_OBJ_CREATOR_SHARPCLAW_OBJECT_ID       0x11
#define DFSH_OBJ_CREATOR_EFFECT_RESOURCE_ID        0x82
#define DFSH_OBJ_CREATOR_DISABLE_GAME_BIT          0x589
#define DFSH_OBJ_CREATOR_TRIGGER_GAME_BIT_BASE     0xF6
#define DFSH_OBJ_CREATOR_DROPPED_ITEM_GAME_BIT     0xFC
#define DFSH_OBJ_CREATOR_SHARPCLAW_GAME_BIT        0x1E7
#define DFSH_OBJ_CREATOR_SHARPCLAW_DROPPED_ITEM_ID 0x49
#define DFSH_OBJ_CREATOR_SHARPCLAW_INITIAL_WEAPON  3
#define DFSH_OBJ_CREATOR_SHARPCLAW_FLAGS           2
#define DFSH_OBJ_CREATOR_SPAWN_TIMER               100

int dfshObjCreator_getExtraSize(void) {
    return sizeof(DFSHObjCreatorState);
}

int dfshObjCreator_getObjectTypeId(void) {
    return 0;
}

void dfshObjCreator_free(void) {
}

void dfshObjCreator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    s32 isVisible;

    isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dfshObjCreator_hitDetect(void) {
}

void dfshObjCreator_update(GameObject* obj) {
    const DFSHObjCreatorPlacement* placement;
    DFSHObjCreatorState* state;
    Dll82Interface** effectResource;
    EnemyPlacement* sharpClawSetup;
    u8 canSetupObject;

    placement = (const DFSHObjCreatorPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (mainGetBit(DFSH_OBJ_CREATOR_DISABLE_GAME_BIT) != 0) {
        obj->userData2 = 0;
        return;
    }

    if (obj->userData2 == 0 &&
        mainGetBit(placement->triggerGameBitOffset + DFSH_OBJ_CREATOR_TRIGGER_GAME_BIT_BASE) != 0) {
        effectResource = Resource_Acquire(DFSH_OBJ_CREATOR_EFFECT_RESOURCE_ID, 1);
        (*effectResource)->spawn(obj, 0, NULL, 1, -1, NULL);
        (*effectResource)->spawn(obj, 1, NULL, 1, -1, NULL);
        Sfx_PlayFromObject(obj, SFXTRIG_hitpos_6);
        Resource_Release(effectResource);
        state->spawnTimerRate = 1;
        obj->userData2 = 1;
    }

    if (state->spawnTimerRate != 0) {
        state->spawnTimer = (s16)(state->spawnTimer - state->spawnTimerRate * (int)timeDelta);
    }

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject > 0 && state->spawnTimer <= 0) {
        sharpClawSetup = (EnemyPlacement*)Obj_AllocObjectSetup(sizeof(EnemyPlacement),
                                                                             DFSH_OBJ_CREATOR_SHARPCLAW_OBJECT_ID);
        sharpClawSetup->base.posX = placement->base.posX;
        sharpClawSetup->base.posY = placement->base.posY;
        sharpClawSetup->base.posZ = placement->base.posZ;
        sharpClawSetup->base.ident = placement->base.ident;
        sharpClawSetup->base.color[0] = placement->base.color[0];
        sharpClawSetup->base.color[1] = placement->base.color[1];
        sharpClawSetup->base.color[2] = placement->base.color[2];
        sharpClawSetup->base.color[3] = placement->base.color[3];
        sharpClawSetup->initialWeaponId = DFSH_OBJ_CREATOR_SHARPCLAW_INITIAL_WEAPON;
        sharpClawSetup->gameBit = DFSH_OBJ_CREATOR_SHARPCLAW_GAME_BIT;
        sharpClawSetup->unk30 = -1;
        sharpClawSetup->gameBit2 = -1;
        sharpClawSetup->unk1C = -1;
        sharpClawSetup->initialYaw = (s8)(obj->anim.rotX >> 8);
        sharpClawSetup->flags = DFSH_OBJ_CREATOR_SHARPCLAW_FLAGS;
        if (mainGetBit(DFSH_OBJ_CREATOR_DROPPED_ITEM_GAME_BIT) != 0) {
            sharpClawSetup->droppedItemId = DFSH_OBJ_CREATOR_SHARPCLAW_DROPPED_ITEM_ID;
        } else {
            sharpClawSetup->droppedItemId = -1;
        }
        sharpClawSetup->aggroRangeByte = 0xFF;
        sharpClawSetup->triggerSequenceId = -1;
        sharpClawSetup->unk34 = 0xFFFF;
        objSetupObject(&sharpClawSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        state->spawnTimer = DFSH_OBJ_CREATOR_SPAWN_TIMER;
        state->spawnTimerRate = 0;
    }
}

void dfshObjCreator_init(GameObject* obj, const DFSHObjCreatorPlacement* placement) {
    DFSHObjCreatorState* state;

    state = obj->extra;
    obj->anim.rotX = (s16)((s32)placement->initialYaw << 8);
    obj->userData2 = 0;
    state->spawnTimer = DFSH_OBJ_CREATOR_SPAWN_TIMER;
    state->spawnTimerRate = 0;
    obj->anim.renderAlpha = 0xFF;
    obj->anim.alpha = 0xFF;
}

void dfshObjCreator_release(void) {
}

void dfshObjCreator_initialise(void) {
}

ObjectDescriptor gDFSHObjCreatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dfshObjCreator_initialise,
    (ObjectDescriptorCallback)dfshObjCreator_release,
    0,
    (ObjectDescriptorCallback)dfshObjCreator_init,
    (ObjectDescriptorCallback)dfshObjCreator_update,
    (ObjectDescriptorCallback)dfshObjCreator_hitDetect,
    (ObjectDescriptorCallback)dfshObjCreator_render,
    (ObjectDescriptorCallback)dfshObjCreator_free,
    (ObjectDescriptorCallback)dfshObjCreator_getObjectTypeId,
    dfshObjCreator_getExtraSize,
};
