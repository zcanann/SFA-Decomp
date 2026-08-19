/*
 * DLL 660 - a temple door/aperture object in the CloudRunner
 * Fortress (WC) area. Each instance counts down a timer and toggles between
 * two trigger sequences (closed→open, open→closed) when the player activates
 * the hitbox interaction flag. The 'type' field from placement sets the
 * object's X rotation.
 */
#include "main/dll/dll_0294_wctemple.h"
#include "main/frame_timing.h"
#include "main/objseq.h"
#include "main/object_render.h"

#define WCTEMPLE_EXTRA_SIZE           8
#define WCTEMPLE_SEQUENCE_SLOT_CLOSED 0
#define WCTEMPLE_SEQUENCE_SLOT_OPEN   1

int wctemple_getExtraSize(void) {
    return WCTEMPLE_EXTRA_SIZE;
}

int wctemple_getObjectTypeId(void) {
    return 0;
}

void wctemple_free(void) {
}

void wctemple_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void wctemple_hitDetect(void) {
}

void wctemple_update(GameObject* obj) {
    WCTempleState* state = obj->extra;

    state->timer -= timeDelta;
    if (state->timer < 0.0f) {
        state->timer = 0.0f;
    }

    if (state->triggerSlot == WCTEMPLE_SEQUENCE_SLOT_CLOSED) {
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            (*gObjectTriggerInterface)
                ->runSequence(WCTEMPLE_SEQUENCE_SLOT_CLOSED, obj, -1);
            state->triggerSlot = WCTEMPLE_SEQUENCE_SLOT_OPEN;
        }
    } else {
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            (*gObjectTriggerInterface)
                ->runSequence(WCTEMPLE_SEQUENCE_SLOT_OPEN, obj, -1);
            state->triggerSlot = WCTEMPLE_SEQUENCE_SLOT_CLOSED;
        }
    }
}

void wctemple_init(GameObject* obj, WCTempleSetup* setup) {
    int angle = setup->type;
    obj->anim.rotX = angle << 8;
}

void wctemple_release(void) {
}

void wctemple_initialise(void) {
}

ObjectDescriptor gWCTempleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wctemple_initialise,
    (ObjectDescriptorCallback)wctemple_release,
    0,
    (ObjectDescriptorCallback)wctemple_init,
    (ObjectDescriptorCallback)wctemple_update,
    (ObjectDescriptorCallback)wctemple_hitDetect,
    (ObjectDescriptorCallback)wctemple_render,
    (ObjectDescriptorCallback)wctemple_free,
    (ObjectDescriptorCallback)wctemple_getObjectTypeId,
    wctemple_getExtraSize,
};
