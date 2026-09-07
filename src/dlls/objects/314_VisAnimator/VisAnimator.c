/* Tracks a game-bit-controlled visibility state for the containing map block. */
#include "dlls/objects/314_VisAnimator.h"

#include "game/objects/object.h"
#include "main/gamebits_api.h"
#include "main/lightmap_api.h"

int VisAnimator_getExtraSize(void) {
    return sizeof(VisAnimatorState);
}

int VisAnimator_getObjectTypeId(void) {
    return 0;
}

void VisAnimator_free(void) {
}

void VisAnimator_render(void) {
}

void VisAnimator_hitDetect(void) {
}

void VisAnimator_update(GameObject* obj) {
    VisAnimatorPlacement* placement = (VisAnimatorPlacement*)obj->anim.placementData;
    VisAnimatorState* state = obj->extra;
    int blockIndex =
        objPosToMapBlockIdx((double)obj->anim.localPosX, (double)obj->anim.localPosY, (double)obj->anim.localPosZ);
    int gateValue;

    if (mapGetBlock(blockIndex) == NULL) {
        state->flags |= VIS_ANIMATOR_STATE_REFRESH_PENDING;
        return;
    }
    gateValue = mainGetBit(placement->gateGameBit);
    state->currentGateState = (u8)(state->gateMask & gateValue);
    if (state->previousGateState != state->currentGateState) {
        state->visibilityBit ^= 1;
        state->flags |= VIS_ANIMATOR_STATE_REFRESH_PENDING;
    }
    state->previousGateState = state->currentGateState;
    if (state->flags & VIS_ANIMATOR_STATE_REFRESH_PENDING) {
        state->flags &= ~VIS_ANIMATOR_STATE_REFRESH_PENDING;
    }
}

void VisAnimator_init(GameObject* obj, VisAnimatorPlacement* placement) {
    VisAnimatorState* state;
    u32 gateValue;
    u8 gateState;
    int initialVisibility;

    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    state = obj->extra;
    initialVisibility = placement->initialVisibilityBit;
    state->visibilityBit = initialVisibility;
    state->gateMask = (u8)(1 << placement->gateBitIndex);
    gateValue = mainGetBit(placement->gateGameBit);
    if ((state->gateMask & gateValue) != 0) {
        state->visibilityBit ^= 1;
    }
    mapGetBlock(
        objPosToMapBlockIdx((double)obj->anim.localPosX, (double)obj->anim.localPosY, (double)obj->anim.localPosZ));
    gateValue = mainGetBit(placement->gateGameBit);
    gateState = (u8)(state->gateMask & gateValue);
    state->currentGateState = gateState;
    state->previousGateState = gateState;
    state->flags |= VIS_ANIMATOR_STATE_REFRESH_PENDING;
}

void VisAnimator_release(void) {
}

void VisAnimator_initialise(void) {
}

ObjectDescriptor gVisAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VisAnimator_initialise,
    (ObjectDescriptorCallback)VisAnimator_release,
    0,
    (ObjectDescriptorCallback)VisAnimator_init,
    (ObjectDescriptorCallback)VisAnimator_update,
    (ObjectDescriptorCallback)VisAnimator_hitDetect,
    (ObjectDescriptorCallback)VisAnimator_render,
    (ObjectDescriptorCallback)VisAnimator_free,
    (ObjectDescriptorCallback)VisAnimator_getObjectTypeId,
    VisAnimator_getExtraSize,
};
