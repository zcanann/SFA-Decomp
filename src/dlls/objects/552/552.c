/*
 * Volcano Force Point Temple SpellStone placement (DLL 552). Using the required
 * fire SpellStone completes the placement, clears its activation bit, and
 * disables interaction. Map acts select the first or second SpellStone.
 */
#include "dlls/objects/552.h"

#include "main/gamebit_ids.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/objprint_render_api.h"


#define VFP_SPPL_ACT_FIRST_STONE 1
#define VFP_SPPL_ACT_SECOND_STONE 2
#define VFP_SPPL_ROTATION_BYTE_SHIFT 8

int VFP_SpellPlace_getExtraSize(void)
{
    return sizeof(VfpSpellPlaceState);
}

int VFP_SpellPlace_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_SpellPlace_free(void)
{
}

void VFP_SpellPlace_render(void)
{
}

void VFP_SpellPlace_hitDetect(void)
{
}

void VFP_SpellPlace_update(GameObject* spellPlace)
{
    VfpSpellPlaceState* state;
    u8 mapAct;

    if (((VfpSpellPlaceState*)spellPlace->extra)->completionLatched == 0 &&
        mainGetBit((int)((VfpSpellPlaceState*)spellPlace->extra)->activationGameBit) != 0)
    {
        spellPlace->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    }
    else
    {
        spellPlace->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    objUpdateHitVolumeTransforms(spellPlace);
    if (spellPlace->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED)
    {
        mapAct = (*gMapEventInterface)->getMapAct((int)spellPlace->anim.mapEventSlot);
        switch (mapAct)
        {
        case VFP_SPPL_ACT_FIRST_STONE:
            state = spellPlace->extra;
            if ((*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_FireSpellStone1_Got) != 0)
            {
                mainSetBits(state->completionGameBit, 1);
                mainSetBits(state->activationGameBit, 0);
                state->completionLatched = 1;
                spellPlace->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
            break;
        case VFP_SPPL_ACT_SECOND_STONE:
            state = spellPlace->extra;
            if ((*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_FireSpellStone2_Got) != 0)
            {
                mainSetBits(state->completionGameBit, 1);
                mainSetBits(state->activationGameBit, 0);
                state->completionLatched = 1;
                spellPlace->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
            break;
        }
    }
}

void VFP_SpellPlace_init(GameObject* spellPlace, VfpSpellPlacePlacementPrefix* mapData)
{
    VfpSpellPlaceState* state;

    state = spellPlace->extra;
    state->completionGameBit = mapData->completionGameBit;
    state->activationGameBit = mapData->activationGameBit;
    state->completionLatched = 0;
    spellPlace->anim.rotX = (s16)(mapData->rotationXByte << VFP_SPPL_ROTATION_BYTE_SHIFT);
    if (mainGetBit(state->completionGameBit) != 0)
    {
        state->completionLatched = 1;
        spellPlace->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    spellPlace->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED | OBJECT_OBJFLAG_HIDDEN;
}

void VFP_SpellPlace_release(void)
{
}

void VFP_SpellPlace_initialise(void)
{
}

ObjectDescriptor gVFP_SpellPlaceObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    VFP_SpellPlace_initialise,
    VFP_SpellPlace_release,
    0,
    (ObjectDescriptorCallback)VFP_SpellPlace_init,
    (ObjectDescriptorCallback)VFP_SpellPlace_update,
    VFP_SpellPlace_hitDetect,
    VFP_SpellPlace_render,
    VFP_SpellPlace_free,
    (ObjectDescriptorCallback)VFP_SpellPlace_getObjectTypeId,
    VFP_SpellPlace_getExtraSize,
};
