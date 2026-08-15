/*
 * Timed Tricky guard spot (DLL slot 288 / 0x120).
 *
 * Offers Tricky's guard command while inactive, tracks him inside the spot's
 * radius while guarding, and recalls him when the configured timer expires.
 */
#include "dlls/objects/288_TrickyGuard.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/objprint_render_api.h"
#include "main/objtype.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects/lifecycle.h"

#define TRICKY_GUARD_SPOT_GROUP             0x1E
#define TRICKY_GUARD_SPOT_FRAMES_PER_SECOND 60


int TrickyGuardSpot_getExtraSize(void) {
    return sizeof(TrickyGuardSpotState);
}

void TrickyGuardSpot_free(GameObject* obj) {
    objFreeObjectType(obj, TRICKY_GUARD_SPOT_GROUP);
}

void TrickyGuardSpot_render(void) {
}

void TrickyGuardSpot_update(GameObject* obj) {
    TrickyGuardSpotState* state;
    TrickyGuardSpotPlacement* placement;
    GameObject* tricky;
    TrickyGuardSpotStateFlags* stateFlags;

    state = obj->extra;
    placement = (TrickyGuardSpotPlacement*)obj->anim.placementData;
    tricky = getTrickyObject();
    stateFlags = &state->flags;
    obj->anim.resetHitboxFlags = (u8)(obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
    stateFlags->trickyInRange = 0;
    if (tricky != NULL) {
        if (TRICKY_INTERFACE(tricky)->isGuarding(tricky) != 0) {
            if (Vec_xzDistance(&obj->anim.worldPosX, &tricky->anim.worldPosX) < (f32)(s32)placement->triggerRadius) {
                state->guardTimer = state->guardTimer - framesThisStep;
                stateFlags->trickyInRange = 1;
            }
        }
    }
    if (state->guardTimer != 0) {
        if (tricky != NULL && TRICKY_INTERFACE(tricky)->isGuarding(tricky) == 0) {
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
                TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_GUARD_COMMAND_KIND,
                                                                    TRICKY_GUARD_COMMAND_TYPE);
            }
            obj->anim.resetHitboxFlags = (u8)(obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
            objUpdateHitVolumeTransforms(obj);
        }
    } else if (tricky != NULL) {
        TRICKY_INTERFACE(tricky)->requestRecall(tricky);
        state->guardTimer = placement->guardDurationSeconds * TRICKY_GUARD_SPOT_FRAMES_PER_SECOND;
    }
    mainSetBits(placement->trickyInRangeGameBit, stateFlags->trickyInRange);
}

void TrickyGuardSpot_init(GameObject* obj, TrickyGuardSpotPlacement* placement) {
    TrickyGuardSpotState* state = obj->extra;

    objAddObjectType(obj, TRICKY_GUARD_SPOT_GROUP);
    state->guardTimer = placement->guardDurationSeconds * TRICKY_GUARD_SPOT_FRAMES_PER_SECOND;
    obj->anim.rotX = (s16)(s32)placement->rotationX;
}

ObjectDescriptor gTrickyGuardSpotObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)TrickyGuardSpot_init,
    (ObjectDescriptorCallback)TrickyGuardSpot_update,
    0,
    (ObjectDescriptorCallback)TrickyGuardSpot_render,
    (ObjectDescriptorCallback)TrickyGuardSpot_free,
    0,
    TrickyGuardSpot_getExtraSize,
};
