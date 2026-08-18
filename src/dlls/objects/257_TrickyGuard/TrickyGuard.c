/*
 * DLL 0x101 - TrickyGuard.
 *
 * Directs an available Tricky to guard this object's position when its
 * optional game-bit condition is met and the player enters range.
 */
#include "dlls/objects/257_TrickyGuard.h"
#include "dlls/objects/288_TrickyGuard.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/gamebits.h"
#include "main/objprint_render_api.h"
#include "sys/objects/lifecycle.h"

#define TRICKYGUARD_GAMEBIT_NONE   -1

void TrickyGuard_update(GameObject* obj) {
    GameObject* tricky;
    TrickyGuardPlacement* placement = (TrickyGuardPlacement*)obj->anim.placementData;

    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (placement->armingGameBit != TRICKYGUARD_GAMEBIT_NONE) {
        if (mainGetBit(placement->armingGameBit) == 0) {
            return;
        }
    }
    tricky = getTrickyObject();
    if (tricky == NULL) {
        return;
    }
    if (TRICKY_INTERFACE(tricky)->isGuarding(tricky) != 0) {
        return;
    }
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
        TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_GUARD_COMMAND_KIND,
                                                      TRICKY_GUARD_COMMAND_TYPE);
    }
    obj->anim.resetHitboxFlags = (u8)(obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
    objUpdateHitVolumeTransforms(obj);
}

void TrickyGuard_init(GameObject* obj, TrickyGuardPlacement* placement) {

    obj->anim.rotX = placement->rotXByte << 8;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
}

ObjectDescriptor gTrickyGuardObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)TrickyGuard_init,
    (ObjectDescriptorCallback)TrickyGuard_update,
    0,
    0,
    0,
    0,
    0,
};
