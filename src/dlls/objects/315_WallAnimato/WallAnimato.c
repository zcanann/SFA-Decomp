/* Tricky-activated wall that emits debris while its completion timer advances. */
#include "dlls/objects/315_WallAnimato.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/partfx_interface.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/objprint_render_api.h"
#include "main/vecmath.h"
#include "main/objtype.h"
#include "sys/objects/lifecycle.h"

#define WALL_ANIMATOR_DONE_TIMER               3000
#define WALL_ANIMATOR_GROUP_SECONDARY          0x31
#define WALL_ANIMATOR_NEARBY_GROUP             5
#define WALL_ANIMATOR_PARTFX_DEBRIS            0xCA
#define WALL_ANIMATOR_PARTFX_DUST              0xCB
#define WALL_ANIMATOR_PARTFX_FLAGS             0x200001

u8 WallAnimator_getEnergyCost(GameObject* obj) {
    WallAnimatorPlacement* placement = (WallAnimatorPlacement*)obj->anim.placementData;

    return (u8)placement->spawnRotZ;
}

u8 WallAnimator_isComplete(GameObject* obj) {
    WallAnimatorState* state = obj->extra;

    return state->timer >= WALL_ANIMATOR_DONE_TIMER;
}

f32 WallAnimator_applyImpact(GameObject* obj, GameObject* target) {
    PartFxSpawnParams spawn;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 offset[3];
    WallAnimatorPlacement* placement;
    int burstCount;
    WallAnimatorState* state;
    f32 scale;

    placement = (WallAnimatorPlacement*)obj->anim.placementData;
    burstCount = 6;
    do {
        offset[0] = 0.13f * (f32)randomGetRange(-0x64, 0x64);
        offset[1] = 0.0f;
        offset[2] = 0.0f;
        spawn.rotZ = randomGetRange(-0x7FFF, 0x8000);
        spawn.rotY = 0;
        spawn.rotX = 0;
        vecRotateZXY(&spawn.rotX, offset);
        offset[2] -= 25.0f;
        vecRotateZXY((void*)obj, offset);
        spawn.rotZ = placement->spawnRotZ;
        spawn.rotX = obj->anim.rotX;
        spawn.posX = obj->anim.worldPosX + offset[0];
        spawn.posY = 15.0f + (obj->anim.worldPosY + offset[1]);
        spawn.posZ = obj->anim.worldPosZ + offset[2];
        (*gPartfxInterface)
            ->spawnObject((void*)obj, WALL_ANIMATOR_PARTFX_DEBRIS, &spawn, WALL_ANIMATOR_PARTFX_FLAGS, -1, NULL);
        (*gPartfxInterface)
            ->spawnObject((void*)obj, WALL_ANIMATOR_PARTFX_DUST, &spawn, WALL_ANIMATOR_PARTFX_FLAGS, -1, NULL);
        burstCount--;
    } while (burstCount != 0);

    state = obj->extra;
    deltaY = target->anim.localPosY - obj->anim.localPosY;
    if ((deltaY < -20.0f) || (deltaY > 20.0f)) {
        scale = 0.0f;
    } else {
        deltaX = target->anim.localPosX - obj->anim.localPosX;
        deltaZ = target->anim.localPosZ - obj->anim.localPosZ;
        if (deltaX * deltaX + deltaZ * deltaZ > 2500.0f) {
            scale = 0.0f;
        } else {
            state->timer += 0x3C;
            scale = state->timer / 3000.0f;
        }
    }
    return scale;
}

int WallAnimator_getExtraSize(void) {
    return sizeof(WallAnimatorState);
}

void WallAnimator_free(GameObject* obj) {
    objFreeObjectType(obj, WALL_ANIMATOR_GROUP_CLIMBABLE);
    objFreeObjectType(obj, WALL_ANIMATOR_GROUP_SECONDARY);
}

void WallAnimator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void WallAnimator_update(GameObject* obj) {
    GameObject* nearbyObject;
    WallAnimatorState* state;
    WallAnimatorPlacement* placement;
    GameObject* tricky;
    f32 nearestDistance[4];

    state = obj->extra;
    placement = (WallAnimatorPlacement*)obj->anim.placementData;
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;

    if (state->complete != 0) {
        return;
    }

    if (state->timer >= WALL_ANIMATOR_DONE_TIMER) {
        state->complete = 1;
        mainSetBits((int)placement->completionBit, 1);
        Sfx_PlayFromObject(obj, SFXTRIG_menuups16k);
        return;
    }

    tricky = getTrickyObject();
    if (tricky != NULL) {
        nearestDistance[0] = 35.0f;
        nearbyObject = objGetNearestTypeTo(WALL_ANIMATOR_NEARBY_GROUP, obj, nearestDistance);
        if (nearbyObject == NULL) {
            obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_PROMPT_SUPPRESSED;
            obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
                TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_COMMAND_KIND_PRIORITY, 1);
            }
            objUpdateHitVolumeTransforms(obj);
        }
    } else {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
}

void WallAnimator_init(GameObject* objAddress, WallAnimatorPlacement* placement) {
    WallAnimatorState* state;

    state = objAddress->extra;
    objAddress->anim.rotX = placement->initialRotX;
    objAddObjectType(objAddress, WALL_ANIMATOR_GROUP_CLIMBABLE);
    objAddObjectType(objAddress, WALL_ANIMATOR_GROUP_SECONDARY);
    if (mainGetBit((int)placement->completionBit) != 0) {
        state->complete = 1;
        state->timer = WALL_ANIMATOR_DONE_TIMER;
    }
}

ObjectDescriptor14 gWallAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)WallAnimator_init,
    (ObjectDescriptorCallback)WallAnimator_update,
    0,
    (ObjectDescriptorCallback)WallAnimator_render,
    (ObjectDescriptorCallback)WallAnimator_free,
    0,
    WallAnimator_getExtraSize,
    (ObjectDescriptorCallback)WallAnimator_applyImpact,
    (ObjectDescriptorCallback)WallAnimator_isComplete,
    (ObjectDescriptorCallback)WallAnimator_getEnergyCost,
    0,
};
