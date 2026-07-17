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

