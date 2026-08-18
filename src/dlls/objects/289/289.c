/*
 * Reusable information-text trigger object (DLL slot 289 / 0x121).
 *
 * Displays the selected model help-text entry while its trigger is active and
 * the player remains inside the object's interaction range.
 */
#include "dlls/objects/289.h"
#include "game/objects/object.h"
#include "main/frame_timing.h"
#include "main/minimap_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/obj_trigger.h"
#include "main/objprint_render_api.h"
#include "sys/objects.h"

#define INFO_TEXT_DISPLAY_DURATION 600.0f

int infotext_getExtraSize(void) {
    return sizeof(InfoTextState);
}

void infotext_update(GameObject* obj) {
    InfoTextState* state = obj->extra;

    if (ObjTrigger_IsSet(obj) != 0 && isAreaNameTextActive() == 0) {
        state->displayTimer = INFO_TEXT_DISPLAY_DURATION;
    }
    if (state->displayTimer > 0.0f) {
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) == 0) {
            state->displayTimer = 0.0f;
        } else {
            state->displayTimer = state->displayTimer - timeDelta;
            showHelpText(
                obj->anim.modelInstance->helpTextIds[((InfoTextPlacement*)obj->anim.placementData)->hintTextIndex]);
        }
    }
    if ((obj->anim.modelInstance->flags & OBJDEF_FLAG_HAS_MODELS) != 0) {
        objUpdateHitVolumeTransforms(obj);
    }
}

void infotext_init(GameObject* obj, InfoTextPlacement* placement) {
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->anim.rotX = placement->rotationX << 8;
    objSetHintTextIdx(obj, placement->hintTextIndex);
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
