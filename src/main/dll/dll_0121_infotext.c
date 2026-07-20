/* DLL 0x0121 - infotext. TU: 0x8018B9F0-0x8018BB00. */
#include "main/game_object.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/objprint_render_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/minimap_api.h"
#include "main/object_descriptor.h"
#include "main/dll/dll_0121_infotext.h"

int infotext_getExtraSize(void) { return sizeof(InfoTextState); }

void infotext_update(GameObject* obj)
{
    InfoTextState* state;
    GameObject* objReg = obj;

    state = objReg->extra;
    if (ObjTrigger_IsSet((int)obj) != 0 && isAreaNameTextActive() == 0)
    {
        state->displayTimer = 600.0f;
    }
    if (state->displayTimer > 0.0f)
    {
        if ((objReg->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) == 0)
        {
            state->displayTimer = 0.0f;
        }
        else
        {
            state->displayTimer = state->displayTimer - timeDelta;
            showHelpText(objReg->anim.modelInstance->helpTextIds[
                ((InfoTextSetup*)objReg->anim.placementData)->hintTextIndex]);
        }
    }
    if ((objReg->anim.modelInstance->flags & OBJDEF_FLAG_HAS_MODELS) != 0)
    {
        objRenderFn_80041018(objReg);
    }
}

void infotext_init(GameObject* obj, InfoTextSetup* setup)
{
    u32 flags;
    flags = (u32)obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->objectFlags = flags;
    obj->anim.rotX = (s16)((s32)(u8)setup->rotation << 8);
    objSetHintTextIdx(obj, (u8)setup->hintTextIndex);
}

ObjectDescriptor gInfoTextObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)infotext_init,
    (ObjectDescriptorCallback)infotext_update,
    0,
    0,
    0,
    0,
    infotext_getExtraSize,
};
