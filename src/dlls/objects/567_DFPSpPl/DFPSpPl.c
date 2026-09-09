/*
 * Ocean Force Point Temple spellstone placement. It remains enabled while its
 * activation GameBit is set; using the required water SpellStone sets
 * the completion GameBit, clears the activation bit, and disables itself.
 */
#include "dlls/objects/567_DFPSpPl.h"

#include "main/gamebit_ids.h"
#include "main/game_ui_interface.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/objprint_render_api.h"

#define DFP_SPPL_ACT_FIRST_STONE           1
#define DFP_SPPL_ACT_SECOND_STONE          2
#define DFP_SPPL_ROTATION_BYTE_SHIFT       8
#define DFP_SPPL_THORNTAIL_MAP_SLOT        7
#define DFP_SPPL_WALLED_CITY_MAP_SLOT      0xd
#define DFP_SPPL_THORNTAIL_COMPLETED_ACT   8
#define DFP_SPPL_WALLED_CITY_COMPLETED_ACT 2

int DFPSpPl_getExtraSize(void) {
    return sizeof(DfpSpellPlaceState);
}

int DFPSpPl_getObjectTypeId(void) {
    return 0;
}

void DFPSpPl_free(void) {
}

void DFPSpPl_render(void) {
}

void DFPSpPl_hitDetect(void) {
}

void DFPSpPl_update(GameObject* obj) {
    DfpSpellPlaceState* state;
    u32 activationGameBitSet;
    int itemUsed;
    int mapAct;

    if ((((DfpSpellPlaceState*)obj->extra)->completionLatched == '\0') &&
        (activationGameBitSet = mainGetBit((int)((DfpSpellPlaceState*)obj->extra)->activationGameBit),
         activationGameBitSet != 0)) {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    objUpdateHitVolumeTransforms(obj);
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
        mapAct = (u8)(*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
        switch (mapAct) {
        case DFP_SPPL_ACT_FIRST_STONE:
            state = obj->extra;
            itemUsed = (*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_WaterSpellStone1_Got);
            if (itemUsed != 0) {
                mainSetBits((int)state->completionGameBit, 1);
                mainSetBits((int)state->activationGameBit, 0);
                state->completionLatched = 1;
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
            break;
        case DFP_SPPL_ACT_SECOND_STONE:
            state = obj->extra;
            itemUsed = (*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_WaterSpellStone2_Got);
            if (itemUsed != 0) {
                mainSetBits((int)state->completionGameBit, 1);
                mainSetBits((int)state->activationGameBit, 0);
                state->completionLatched = 1;
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                (*gMapEventInterface)->setMapAct(DFP_SPPL_THORNTAIL_MAP_SLOT, DFP_SPPL_THORNTAIL_COMPLETED_ACT);
                (*gMapEventInterface)->setMapAct(DFP_SPPL_WALLED_CITY_MAP_SLOT, DFP_SPPL_WALLED_CITY_COMPLETED_ACT);
            }
            break;
        }
    }
    return;
}

void DFPSpPl_init(GameObject* obj, DfpSpellPlacePlacementPrefix* mapData) {
    DfpSpellPlaceState* state;
    u32 completionGameBitSet;

    state = obj->extra;
    state->completionGameBit = mapData->completionGameBit;
    state->activationGameBit = mapData->activationGameBit;
    state->completionLatched = 0;
    obj->anim.rotX = (s16)(mapData->rotationXByte << DFP_SPPL_ROTATION_BYTE_SHIFT);
    completionGameBitSet = mainGetBit((int)state->completionGameBit);
    if (completionGameBitSet != 0) {
        state->completionLatched = 1;
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HITDETECT_DISABLED | OBJECT_OBJFLAG_HIDDEN));
    return;
}

void DFPSpPl_release(void) {
}

void DFPSpPl_initialise(void) {
}

ObjectDescriptor gDFPSpPlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    DFPSpPl_initialise,
    DFPSpPl_release,
    0,
    (ObjectDescriptorCallback)DFPSpPl_init,
    (ObjectDescriptorCallback)DFPSpPl_update,
    DFPSpPl_hitDetect,
    DFPSpPl_render,
    DFPSpPl_free,
    (ObjectDescriptorCallback)DFPSpPl_getObjectTypeId,
    DFPSpPl_getExtraSize,
};
