/*
 * BombPlantin (DLL 0x1AB) - an interactive spot where the player plants a
 * bomb spore. Placement game bits gate the prompt and record the planted spot.
 */
#include "dlls/objects/427_BombPlantin.h"

#include "game/objects/object.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/obj_trigger.h"
#include "main/objprint_render_api.h"
#include "main/objseq.h"

void BombPlantingSpot_update(GameObject* obj) {
    const BombPlantingSpotPlacement* placement = (const BombPlantingSpotPlacement*)obj->anim.placementData;
    s32 requiredGameBit;

    obj->anim.rotX = (s16)(placement->rotXByte << 8);

    requiredGameBit = placement->requiredGameBit;
    if (requiredGameBit != -1 && mainGetBit(requiredGameBit) == 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        return;
    }

    if (mainGetBit(GAMEBIT_ITEM_BombSpore_Count) == 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }

    if (ObjTrigger_IsSetById(obj, GAMEBIT_ITEM_BombSpore_Count) != 0) {
        gameBitDecrement(GAMEBIT_ITEM_BombSpore_Count);
        mainSetBits(placement->plantedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
    } else if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0 &&
               mainGetBit(GAMEBIT_SawBombPlantPatch) == 0) {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        mainSetBits(GAMEBIT_SawBombPlantPatch, 1);
    }

    if (mainGetBit(placement->plantedGameBit) == 0) {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        objUpdateHitVolumeTransforms(obj);
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
}

void BombPlantingSpot_init(GameObject* obj, const BombPlantingSpotPlacement* placement) {
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
    obj->anim.rotX = placement->rotXByte << 8;
}

ObjectDescriptor gBombPlantingSpotObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)BombPlantingSpot_init,
    (ObjectDescriptorCallback)BombPlantingSpot_update,
    0,
    0,
    0,
    0,
    0,
};
