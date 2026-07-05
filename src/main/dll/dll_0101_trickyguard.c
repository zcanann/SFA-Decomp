/*
 * trickyguard (DLL 0x0101) - a passive guard volume that, while its
 * arming game bit is set, hands the player's Tricky (the fox companion)
 * a stay/guard command at this object's position.
 *
 * Each frame trickyguard_update arms INTERACT_FLAG_DISABLED, gates on the
 * placement's arming game bit (offset 0x1A; -1 = always armed), fetches
 * the live Tricky object, and - if Tricky is not already busy
 * (TRICKY_VTBL_IS_BUSY) and the player just entered range
 * (INTERACT_FLAG_IN_RANGE) - issues the guard command (TRICKY_VTBL_GUARD:
 * tricky, this, 1, 3) before clearing the disable bit and re-running the
 * object render hook.
 *
 * trickyguard_init seeds rotX from the placement yaw byte and marks the
 * object with TRICKYGUARD_OBJECT_FLAG.
 *
 * This TU is the shared DLL bundle for objects 0x00FE..0x0103 - it also
 * defines the ObjectDescriptors for magicplant, trickywarp, staypoint,
 * duster and curvefish, whose callbacks live in their own TUs (declared
 * in dll_00FE_magicplant.h).
 */
#include "main/game_object.h"
#include "main/dll/dll_00FE_magicplant.h"
#include "main/gamebits.h"
#include "main/dll/player_80295318_shared.h"

/* Tricky vtable slots reached through (tricky + 0x68). */
#define TRICKY_VTBL_IS_BUSY 0x11
#define TRICKY_VTBL_GUARD 0x0A

#define TRICKYGUARD_OBJECT_FLAG 0x4000

typedef struct TrickyguardPlacement
{
    u8 pad00[0x18];
    u8 yawByte; /* 0x18 */
    u8 pad19;
    s16 armingGameBit; /* 0x1A: -1 = always armed */
    u8 pad1C[0x20 - 0x1C];
} TrickyguardPlacement;


extern void objRenderFn_80041018(int* obj);

void trickyguard_init(s16* obj, u8* placement)
{
    u32 flags;
    *obj = (s16)((u32)((TrickyguardPlacement*)placement)->yawByte << 8);
    flags = ((GameObject*)obj)->objectFlags;
    flags |= TRICKYGUARD_OBJECT_FLAG;
    ((GameObject*)obj)->objectFlags = flags;
}

void trickyguard_update(int* obj)
{
    int* tricky;
    TrickyguardPlacement* placement = (TrickyguardPlacement*)((GameObject*)obj)->anim.placementData;
    ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (placement->armingGameBit != -1)
    {
        if ((u32)GameBit_Get(placement->armingGameBit) == 0) return;
    }
    tricky = getTrickyObject();
    if (tricky == NULL) return;
    if ((u8)((int (*)(int*))(**(int***)((char*)tricky + 0x68))[TRICKY_VTBL_IS_BUSY])(tricky) != 0) return;
    if ((((GameObject*)obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
    {
        ((void (*)(int*, int*, int, int))(**(int***)((char*)tricky + 0x68))[TRICKY_VTBL_GUARD])(tricky, obj, 1, 3);
    }
    ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
    objRenderFn_80041018(obj);
}

ObjectDescriptor gMagicPlantObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicPlant_init,
    (ObjectDescriptorCallback)MagicPlant_update,
    0,
    (ObjectDescriptorCallback)MagicPlant_render,
    (ObjectDescriptorCallback)MagicPlant_free,
    (ObjectDescriptorCallback)MagicPlant_getObjectTypeId,
    MagicPlant_getExtraSize,
};

ObjectDescriptor gTrickyWarpObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_init,
    (ObjectDescriptorCallback)trickywarp_update,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_free,
    0,
    trickywarp_getExtraSize,
};

ObjectDescriptor gTrickyGuardObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickyguard_init,
    (ObjectDescriptorCallback)trickyguard_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gStayPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)StayPoint_init,
    (ObjectDescriptorCallback)StayPoint_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gDusterObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)duster_init,
    (ObjectDescriptorCallback)duster_update,
    (ObjectDescriptorCallback)duster_hitDetect,
    (ObjectDescriptorCallback)duster_render,
    0,
    0,
    duster_getExtraSize,
};

ObjectDescriptor gCurveFishObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curvefish_init,
    (ObjectDescriptorCallback)curvefish_update,
    0,
    0,
    0,
    0,
    curvefish_getExtraSize,
};
