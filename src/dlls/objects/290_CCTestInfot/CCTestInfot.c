/*
 * Cape Claw disguise-sensitive information prompt (DLL slot 290 / 0x122).
 *
 * Tracks the player's disguise state, selects the corresponding model and
 * help-text entry, and displays that text after its trigger fires while the
 * player remains inside the interaction range.
 */
#include "dlls/objects/290_CCTestInfot.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/minimap_api.h"
#include "main/obj_trigger.h"
#include "sys/objects.h"

#define CC_TEST_INFO_TEXT_DISPLAY_DURATION 600.0f

int CCTestInfot_getExtraSize(void) {
    return sizeof(CCTestInfotState);
}

void CCTestInfot_update(GameObject* obj) {
    CCTestInfotState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();

    if (state->isDisguised != 0) {
        if (playerIsDisguised(player) == 0) {
            state->isDisguised = 0;
        }
    } else {
        if (playerIsDisguised(player) != 0) {
            state->isDisguised = 1;
        }
    }
    objSetHintTextIdx(obj, state->isDisguised);
    Obj_SetActiveModelIndex(obj, state->isDisguised);
    if (ObjTrigger_IsSet(obj) != 0 && isAreaNameTextActive() == 0) {
        state->displayTimer = CC_TEST_INFO_TEXT_DISPLAY_DURATION;
    }
    if (state->displayTimer > 0.0f) {
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) == 0) {
            state->displayTimer = 0.0f;
        } else {
            state->displayTimer = state->displayTimer - timeDelta;
            showHelpText(obj->anim.modelInstance->helpTextIds[state->isDisguised]);
        }
    }
}

void CCTestInfot_init(GameObject* obj, CCTestInfotPlacement* placement) {
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->anim.rotX = placement->rotationX << 8;
    obj->anim.rotY = placement->rotationY << 8;
    obj->anim.rotZ = placement->rotationZ << 8;
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
