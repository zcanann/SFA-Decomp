/*
 * cctestinfot - Cape Claw (mapId 47) "test info" help-prompt object (DLL 0x0122).
 * The object only reacts while the player is disguised: it caches the disguise
 * state, drives the model's hint-text index / active model from it, and -
 * once its ObjTrigger fires - shows help text from the model's helpTextIds
 * table for a fixed hold time.
 */
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/object_api.h"
#include "main/obj_trigger.h"
#include "main/object_descriptor.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/minimap_api.h"
#include "main/dll/CC/dll_0122_cctestinfot.h"
#include "main/dll/CF/dll_012A_cfcrate.h"
#include "main/dll/CF/dll_012B_fxemit.h"
#include "main/dll/dll_010E_deathseq.h"
#include "main/dll/dll_0123_fuelcell.h"
#include "main/dll/dll_0124_deathgas.h"
#include "main/dll/dll_0127_dll127.h"
#include "main/dll/dll_0129_campfire.h"
#include "main/dll/DR/dll_0128_kttorch.h"

#define CCTESTINFOT_OBJFLAG_HIDDEN             0x4000
#define CCTESTINFOT_OBJFLAG_HITDETECT_DISABLED 0x2000
#define CCTESTINFOT_HOLD_TIME_RESET             600.0f
#define CCTESTINFOT_HOLD_TIME_FLOOR             0.0f

int CCTestInfot_getExtraSize(void)
{
    return sizeof(CctestinfotState);
}

void CCTestInfot_update(int* obj)
{
    CctestinfotState* state = ((GameObject*)obj)->extra;
    GameObject* player = Obj_GetPlayerObject();
    if (state->disguised != 0)
    {
        if (playerIsDisguised(player) == 0)
        {
            state->disguised = 0;
        }
    }
    else
    {
        if (playerIsDisguised(player) != 0)
        {
            state->disguised = 1;
        }
    }
    objSetHintTextIdx((GameObject*)obj, state->disguised);
    Obj_SetActiveModelIndex((GameObject*)obj, state->disguised);
    if (ObjTrigger_IsSet((int)obj) != 0 && isAreaNameTextActive() == 0)
    {
        state->holdTimer = CCTESTINFOT_HOLD_TIME_RESET;
    }
    if (state->holdTimer > CCTESTINFOT_HOLD_TIME_FLOOR)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
        {
            state->holdTimer = CCTESTINFOT_HOLD_TIME_FLOOR;
        }
        else
        {
            state->holdTimer = state->holdTimer - timeDelta;
            showHelpText(((GameObject*)obj)->anim.modelInstance->helpTextIds[state->disguised]);
        }
    }
}

void CCTestInfot_init(GameObject* obj, s8* def)
{
    u32 flags;
    flags = (u32)obj->objectFlags | (CCTESTINFOT_OBJFLAG_HIDDEN | CCTESTINFOT_OBJFLAG_HITDETECT_DISABLED);
    obj->objectFlags = flags;
    obj->anim.rotX = (s16)((s32)(u8)def[0x1A] << 8);
    obj->anim.rotY = (s16)((s32)(u8)def[0x19] << 8);
    obj->anim.rotZ = (s16)((s32)(u8)def[0x18] << 8);
}

ObjectDescriptor gCCTestInfotObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)CCTestInfot_init,
    (ObjectDescriptorCallback)CCTestInfot_update,
    0,
    0,
    0,
    0,
    CCTestInfot_getExtraSize,
};

/* Object descriptors exported by this DLL bundle. */
ObjectDescriptor gDeathGasObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS, 0, 0, 0,
    (ObjectDescriptorCallback)DeathGas_init, (ObjectDescriptorCallback)DeathGas_update, 0, 0,
    (ObjectDescriptorCallback)DeathGas_free, 0, DeathGas_getExtraSize,
};
ObjectDescriptor gFuelCellObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS, 0, 0, 0,
    (ObjectDescriptorCallback)FuelCell_init, (ObjectDescriptorCallback)FuelCell_update, 0,
    (ObjectDescriptorCallback)FuelCell_render, (ObjectDescriptorCallback)FuelCell_free, 0,
    FuelCell_getExtraSize,
};
ObjectDescriptor gDeathSeqObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DeathSeq_initialise, (ObjectDescriptorCallback)DeathSeq_release, 0,
    (ObjectDescriptorCallback)DeathSeq_init, (ObjectDescriptorCallback)DeathSeq_update,
    (ObjectDescriptorCallback)DeathSeq_hitDetect, (ObjectDescriptorCallback)DeathSeq_render,
    (ObjectDescriptorCallback)DeathSeq_free, (ObjectDescriptorCallback)DeathSeq_getObjectTypeId,
    DeathSeq_getExtraSize,
};
ObjectDescriptor lbl_80321E58 = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_127_initialise_nop, (ObjectDescriptorCallback)dll_127_release_nop, 0,
    (ObjectDescriptorCallback)dll_127_init, (ObjectDescriptorCallback)dll_127_update,
    (ObjectDescriptorCallback)dll_127_hitDetect_nop, (ObjectDescriptorCallback)dll_127_render,
    (ObjectDescriptorCallback)dll_127_free_nop, (ObjectDescriptorCallback)dll_127_getObjectTypeId,
    dll_127_getExtraSize_ret_0,
};
ObjectDescriptor gCampFireObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS, 0, 0, 0,
    (ObjectDescriptorCallback)CampFire_init, (ObjectDescriptorCallback)CampFire_update, 0,
    (ObjectDescriptorCallback)CampFire_render, (ObjectDescriptorCallback)CampFire_free,
    (ObjectDescriptorCallback)CampFire_getObjectTypeId, CampFire_getExtraSize,
};
ObjectDescriptor gKT_TorchObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)KT_Torch_initialise, (ObjectDescriptorCallback)KT_Torch_release, 0,
    (ObjectDescriptorCallback)KT_Torch_init, (ObjectDescriptorCallback)KT_Torch_update,
    (ObjectDescriptorCallback)KT_Torch_hitDetect, (ObjectDescriptorCallback)KT_Torch_render,
    (ObjectDescriptorCallback)KT_Torch_free, (ObjectDescriptorCallback)KT_Torch_getObjectTypeId,
    KT_Torch_getExtraSize,
};
ObjectDescriptor gCFCrateObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)CFCrate_initialise, (ObjectDescriptorCallback)CFCrate_release, 0,
    (ObjectDescriptorCallback)CFCrate_init, (ObjectDescriptorCallback)CFCrate_update,
    (ObjectDescriptorCallback)CFCrate_hitDetect, (ObjectDescriptorCallback)CFCrate_render,
    (ObjectDescriptorCallback)CFCrate_free, (ObjectDescriptorCallback)CFCrate_getObjectTypeId,
    CFCrate_getExtraSize,
};
ObjectDescriptor gFXEmitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FxEmit_initialise,
    (ObjectDescriptorCallback)FxEmit_release,
    0,
    (ObjectDescriptorCallback)FxEmit_init,
    (ObjectDescriptorCallback)FxEmit_update,
    (ObjectDescriptorCallback)FxEmit_hitDetect,
    (ObjectDescriptorCallback)FxEmit_render,
    (ObjectDescriptorCallback)FxEmit_free,
    (ObjectDescriptorCallback)FxEmit_getObjectTypeId,
    FxEmit_getExtraSize,
};
