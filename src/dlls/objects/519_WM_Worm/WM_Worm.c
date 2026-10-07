/*
 * WM_Worm (DLL 0x0207) - a worm enemy from Warlock Mountain on
 * Dinosaur Planet.
 *
 * While the player is within 440 units of the placement in the XZ plane,
 * the worm drifts toward the player at 1% of the offset per time unit.
 * Positive spawnCountOrInterval values emit that many particles per update;
 * zero emits one particle and marks unknown state; negative values emit one
 * particle, then use their magnitude as a cooldown in obj->userData1. Each
 * spawn update advances the worm's X rotation. Out of range, the worm returns
 * to its recorded home position.
 */
#include "dlls/objects/519_WM_Worm.h"

#include "game/objects/object.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"

int WM_Worm_getExtraSize(void) {
    return sizeof(WMWormState);
}

int WM_Worm_getObjectTypeId(void) {
    return 0;
}

void WM_Worm_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2(obj);
}

void WM_Worm_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }
}

void WM_Worm_hitDetect(void) {
}

void WM_Worm_update(GameObject* obj) {
    f32 dx;
    f32 dy;
    f32 dz;
    GameObject* player;
    WMWormState* state;
    int spawnCountOrInterval;
    int i;
    f32 distance;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (player != NULL) {
        distance = Vec_xzDistance(&player->anim.worldPosX, &((ObjPlacement*)obj->anim.placementData)->posX);
        if (distance > 440.0f) {
            obj->anim.localPosX = state->homeX;
            obj->anim.localPosY = state->homeY;
            obj->anim.localPosZ = state->homeZ;
        } else {
            dx = player->anim.worldPosX - obj->anim.localPosX;
            dy = player->anim.worldPosY - obj->anim.localPosY;
            dz = player->anim.worldPosZ - obj->anim.localPosZ;
            /* Move only along axes where the player position differs. */
            if ((dx > 0.0f) || (dx < 0.0f)) {
                dx = 0.01f * dx;
                obj->anim.localPosX += dx * timeDelta;
            }
            if ((dy > 0.0f) || (dy < 0.0f)) {
                dy = 0.01f * dy;
                obj->anim.localPosY += dy * timeDelta;
            }
            if ((dz > 0.0f) || (dz < 0.0f)) {
                dz = 0.01f * dz;
                obj->anim.localPosZ += dz * timeDelta;
            }
            spawnCountOrInterval = state->spawnCountOrInterval;
            if (spawnCountOrInterval >= 0 || (spawnCountOrInterval < 0 && obj->userData1 <= 0)) {
                if (spawnCountOrInterval == 0) {
                    state->unknown0C = 1;
                }
                obj->anim.rotX += 300;
                if (state->spawnCountOrInterval > 0) {
                    for (i = 0; (s16)i < state->spawnCountOrInterval; i++) {
                        (*gPartfxInterface)->spawnEffect(obj, state->particleEffectId, NULL, 4, -1, NULL);
                    }
                } else {
                    (*gPartfxInterface)->spawnEffect(obj, state->particleEffectId, NULL, 4, -1, NULL);
                }
                obj->userData1 = -state->spawnCountOrInterval;
            } else if (spawnCountOrInterval < 0 && obj->userData1 > 0) {
                obj->userData1 -= framesThisStep;
            }
        }
    }
}

void WM_Worm_init(GameObject* obj, const WMWormPlacementView* placement) {
    WMWormState* state;

    obj->anim.rotX = 0;
    state = obj->extra;
    state->effectScale = (f32)((s32)placement->effectScale << 2);
    state->particleEffectId = placement->particleEffectId;
    state->spawnCountOrInterval = placement->spawnCountOrInterval;
    state->unknown0C = 0;
    if (state->spawnCountOrInterval < 1) {
        obj->userData1 = state->spawnCountOrInterval;
    } else {
        obj->userData1 = 0;
    }
    state->homeX = obj->anim.localPosX;
    state->homeY = obj->anim.localPosY;
    state->homeZ = obj->anim.localPosZ;
}

void WM_Worm_release(void) {
}

void WM_Worm_initialise(void) {
}

ObjectDescriptor gWM_WormObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    WM_Worm_initialise,
    WM_Worm_release,
    0,
    (ObjectDescriptorCallback)WM_Worm_init,
    (ObjectDescriptorCallback)WM_Worm_update,
    WM_Worm_hitDetect,
    (ObjectDescriptorCallback)WM_Worm_render,
    (ObjectDescriptorCallback)WM_Worm_free,
    (ObjectDescriptorCallback)WM_Worm_getObjectTypeId,
    WM_Worm_getExtraSize,
};
