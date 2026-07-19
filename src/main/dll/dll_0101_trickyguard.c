/*
 * trickyguard (DLL 0x0101) - a passive guard volume that, while its
 * arming game bit is set, hands the player's Tricky (the fox companion)
 * a stay/guard command at this object's position.
 *
 * Each frame TrickyGuard_update arms INTERACT_FLAG_DISABLED, gates on the
 * placement's arming game bit (offset 0x1A; -1 = always armed), fetches
 * the live Tricky object, and - if Tricky is not already busy
 * (TRICKY_VTBL_IS_BUSY) and the player just entered range
 * (INTERACT_FLAG_IN_RANGE) - issues the guard command (TRICKY_VTBL_GUARD:
 * tricky, this, 1, 3) before clearing the disable bit and re-running the
 * object render hook.
 *
 * TrickyGuard_init seeds rotX from the placement yaw byte and marks the
 * object with TRICKYGUARD_OBJECT_FLAG.
 *
 * The descriptor follows the implementation below.
 */
#include "main/dll/dll_0101_trickyguard.h"
#include "main/object_descriptor.h"
#include "main/objprint_render_api.h"
#include "main/object.h"
#include "main/gamebits.h"

/* Tricky vtable slots reached through (tricky + 0x68). */
#define TRICKY_VTBL_IS_BUSY 0x11
#define TRICKY_VTBL_GUARD   0x0A

#define TRICKYGUARD_OBJECT_FLAG 0x4000

void TrickyGuard_update(GameObject* obj)
{
    GameObject* tricky;
    TrickyGuardPlacement* placement = (TrickyGuardPlacement*)obj->anim.placementData;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (placement->armingGameBit != -1)
    {
        if ((u32)mainGetBit(placement->armingGameBit) == 0)
            return;
    }
    tricky = getTrickyObject();
    if (tricky == NULL)
        return;
    if ((u8)((int (*)(GameObject*))(**(int***)((char*)tricky + 0x68))[TRICKY_VTBL_IS_BUSY])(tricky) != 0)
        return;
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
    {
        ((void (*)(GameObject*, GameObject*, int, int))(**(int***)((char*)tricky + 0x68))[TRICKY_VTBL_GUARD])(
            tricky, obj, 1, 3);
    }
    obj->anim.resetHitboxFlags = (u8)(obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
    objRenderFn_80041018(obj);
}

void TrickyGuard_init(GameObject* obj, TrickyGuardPlacement* placement)
{
    u32 flags;
    obj->anim.rotX = (s16)((u32)placement->yawByte << 8);
    flags = obj->objectFlags;
    flags |= TRICKYGUARD_OBJECT_FLAG;
    obj->objectFlags = flags;
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
