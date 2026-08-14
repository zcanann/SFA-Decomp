/*
 * DLL 0x1FB (slot 507) - an unnamed interaction-controlled animated object.
 */
#include "dlls/objects/507.h"

#include "dolphin/pad.h"
#include "game/objects/object.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/obj_message.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/pad_api.h"

#define DLL1FB_TRIGGER_MODE_DISABLE_INTERACTION 1
#define DLL1FB_TRIGGER_MODE_DIALOGUE_SEQUENCE   2
#define DLL1FB_DIALOGUE_SEQUENCE_INDEX          4
#define DLL1FB_MESSAGE_QUEUE_CAPACITY           4
#define DLL1FB_MOVE_GROUP_OFFSET                0x100

int dll507_processAnimEvents(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    Dll1FBState* state = obj->extra;
    s16 triggerMode = state->triggerMode;
    u8 interactionFlags;

    (void)unused;
    if (triggerMode == DLL1FB_TRIGGER_MODE_DISABLE_INTERACTION ||
        triggerMode == DLL1FB_TRIGGER_MODE_DIALOGUE_SEQUENCE) {
        interactionFlags = (u8)(obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        obj->anim.resetHitboxFlags = interactionFlags;
    }
    animUpdate->savedFlags = -1;
    animUpdate->movementState = 0;
    return 0;
}

int dll507_getExtraSize(void) {
    return sizeof(Dll1FBState);
}

int dll507_getObjectTypeId(void) {
    return 0;
}

void dll507_free(void) {
}

void dll507_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    Dll1FBState* state = obj->extra;

    if (visible == 0 || state->hideModel != 0u) {
        return;
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void dll507_hitDetect(void) {
}

void dll507_update(GameObject* obj) {
    Dll1FBState* state = obj->extra;

    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0 &&
        state->triggerMode == DLL1FB_TRIGGER_MODE_DIALOGUE_SEQUENCE &&
        mainGetBit(GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE) == 0) {
        (*gObjectTriggerInterface)->runSequence(DLL1FB_DIALOGUE_SEQUENCE_INDEX, obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
        mainSetBits(GAMEBIT_K1_SHRINE_DOOR_DIALOGUE_DONE, 1);
    }
    ObjAnim_AdvanceCurrentMove(obj, 0.01f, timeDelta, NULL);
}

void dll507_init(GameObject* obj, const Dll1FBPlacementView* placement) {
    Dll1FBState* state = obj->extra;
    ObjMsg_AllocQueue(obj, DLL1FB_MESSAGE_QUEUE_CAPACITY);
    obj->animEventCallback = dll507_processAnimEvents;
    obj->anim.rotX = (s16)((s32)placement->rotationXHighByte << 8);
    obj->anim.rotY = placement->rotationY;
    state->baseMove = placement->baseMove;
    state->triggerMode = placement->triggerMode;
    ObjAnim_SetCurrentMove(obj, state->baseMove + DLL1FB_MOVE_GROUP_OFFSET, 0.0f, 0);
}

void dll507_release(void) {
}

void dll507_initialise(void) {
}

ObjectDescriptor gDll1FBObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    dll507_initialise,
    dll507_release,
    0,
    (ObjectDescriptorCallback)dll507_init,
    (ObjectDescriptorCallback)dll507_update,
    dll507_hitDetect,
    (ObjectDescriptorCallback)dll507_render,
    dll507_free,
    (ObjectDescriptorCallback)dll507_getObjectTypeId,
    dll507_getExtraSize,
};
