/* Emits one placement-configured particle burst when its trigger bit is set. */
#include "dlls/objects/317_ExplodeAnim.h"

#include "game/objects/object.h"
#include "main/dll/partfx_interface.h"
#include "main/gamebits.h"
#include "main/objtype.h"
#include "main/vecmath.h"

#define EXPLODE_ANIMATOR_PARTFX_SPAWN_FLAGS 2

int ExplodeAnimator_getExtraSize(void) {
    return sizeof(ExplodeAnimatorState);
}

int ExplodeAnimator_getObjectTypeId(void) {
    return 0;
}

void ExplodeAnimator_free(GameObject* obj) {
    objFreeObjectType(obj, EXPLODE_ANIMATOR_OBJECT_GROUP);
}

void ExplodeAnimator_render(void) {
}

void ExplodeAnimator_hitDetect(void) {
}

void ExplodeAnimator_update(GameObject* obj) {
    int i;
    ExplodeAnimatorState* state;
    ExplodeAnimatorPlacement* placement;
    PartFxSpawnParams spawnParams;
    f32 velocity[2];

    state = obj->extra;
    if ((state->flags & EXPLODE_ANIMATOR_STATE_FIRED) != 0) {
        return;
    }
    placement = (ExplodeAnimatorPlacement*)obj->anim.placementData;
    if (mainGetBit(placement->triggerGameBit) == 0) {
        return;
    }
    mainSetBits(placement->resultGameBit, 1);
    state->flags = (u8)(state->flags | EXPLODE_ANIMATOR_STATE_FIRED);
    for (i = 0; i < placement->particleCount; i++) {
        velocity[0] = 0.01f * (f32)(s32)randomGetRange(placement->velXMin, placement->velXMax);
        velocity[1] = 0.01f * (f32)(s32)randomGetRange(placement->velYMin, placement->velYMax);
        spawnParams.posX = (f32)(s32)randomGetRange(placement->posXMin, placement->posXMax);
        spawnParams.posY = (f32)(s32)randomGetRange(placement->posYMin, placement->posYMax);
        spawnParams.posZ = (f32)(s32)randomGetRange(placement->posZMin, placement->posZMax);
        (*gPartfxInterface)
            ->spawnObject(obj, placement->effectId, &spawnParams, EXPLODE_ANIMATOR_PARTFX_SPAWN_FLAGS, -1, velocity);
    }
}

void ExplodeAnimator_init(GameObject* obj, ExplodeAnimatorPlacement* placement) {
    ExplodeAnimatorState* state = obj->extra;
    int fired;

    if (mainGetBit(placement->resultGameBit) != 0u) {
        fired = EXPLODE_ANIMATOR_STATE_FIRED;
    } else {
        fired = 0;
    }
    state->flags = fired;
    objAddObjectType(obj, EXPLODE_ANIMATOR_OBJECT_GROUP);
}

void ExplodeAnimator_release(void) {
}

void ExplodeAnimator_initialise(void) {
}

ObjectDescriptor gExplodeAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ExplodeAnimator_initialise,
    (ObjectDescriptorCallback)ExplodeAnimator_release,
    0,
    (ObjectDescriptorCallback)ExplodeAnimator_init,
    (ObjectDescriptorCallback)ExplodeAnimator_update,
    (ObjectDescriptorCallback)ExplodeAnimator_hitDetect,
    (ObjectDescriptorCallback)ExplodeAnimator_render,
    (ObjectDescriptorCallback)ExplodeAnimator_free,
    (ObjectDescriptorCallback)ExplodeAnimator_getObjectTypeId,
    ExplodeAnimator_getExtraSize,
};
