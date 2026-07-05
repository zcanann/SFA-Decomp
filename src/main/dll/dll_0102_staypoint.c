/*
 * staypoint (DLL 0x0102) - a "stay here" marker that drives the player's
 * Tricky (the fox companion) to hold position at this object.
 *
 * StayPoint_init marks the object with the 0x4000 object flag.
 *
 * StayPoint_update arms the disable bit each frame, then - while the
 * placement's required game bit is satisfied (-1 = always) - tests whether
 * this is the stay point Tricky is currently assigned to (fn_80138F84).
 * If it is and Tricky is within range (squared distance < lbl_803E38A8) it
 * sets the placement's active game bit and bails. Otherwise it clears the
 * active bit, sets the hit-volume priority from whether a menu item is
 * selected, clears the disable bit, re-runs the object render hook, and -
 * if the player is within range - issues the stay command to Tricky
 * through Tricky's vtable (slot at (tricky + 0x68) -> [0] -> 0x28).
 *
 * This TU is the shared DLL bundle for objects 0x00FE..0x0103: it also
 * defines the ObjectDescriptors for magicplant, trickywarp, trickyguard,
 * duster and curvefish, whose callbacks live in their own TUs (declared in
 * dll_00FE_magicplant.h).
 */
#include "main/game_object.h"
#include "main/dll/dll_00FE_magicplant.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "sfa_light_decls.h"

/* StayPoint_init: object flag set on spawn. */
#define STAYPOINT_OBJECT_FLAG 0x4000

#define STAYPOINT_HITBOX_IN_RANGE 0x4

/* hit-volume priority when a cMenu item is / isn't selected. */
#define STAYPOINT_PRIORITY_MENU 0x10

extern f32 vec3f_distanceSquared(f32* a, f32* b);

extern int fn_80138F84(int tricky); /* current stay-point object for Tricky */
extern f32 lbl_803E38A8; /* stay-point engage radius, squared */

typedef struct StayPointSetup
{
    u8 pad00[0x1e];
    s16 activeGameBit;   /* 0x1E: set while Tricky is staying here; -1 = none */
    s16 requiredGameBit; /* 0x20: gate; -1 = always active */
} StayPointSetup;

void StayPoint_init(u16* obj)
{
    u32 flags;
    flags = ((GameObject*)obj)->objectFlags;
    flags |= STAYPOINT_OBJECT_FLAG;
    ((GameObject*)obj)->objectFlags = flags;
}

void StayPoint_update(int obj)
{
    StayPointSetup* setup;
    void* tricky;
    int isCurrentStayPoint;

    setup = *(StayPointSetup**)&((GameObject*)obj)->anim.placementData;
    tricky = getTrickyObject();
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    if (tricky != NULL)
    {
        isCurrentStayPoint = (obj - fn_80138F84((int)tricky) == 0);
        if (isCurrentStayPoint == 0 && setup->activeGameBit != -1)
        {
            GameBit_Set(setup->activeGameBit, 0);
        }
        if (setup->requiredGameBit == -1 || GameBit_Get(setup->requiredGameBit) != 0)
        {
            if (isCurrentStayPoint != 0 &&
                vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)((int)tricky + 0x18)) < lbl_803E38A8)
            {
                if (setup->activeGameBit != -1)
                {
                    GameBit_Set(setup->activeGameBit, 1);
                }
                return;
            }
            if (cMenuGetSelectedItem() == -1)
            {
                ((GameObject*)obj)->anim.modelInstance->hitVolumes[0].priority = 0;
            }
            else
            {
                ((GameObject*)obj)->anim.modelInstance->hitVolumes[0].priority = STAYPOINT_PRIORITY_MENU;
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (
                u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
            if (((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0) &&
                ((ObjAnimComponent*)obj)->hitVolumeTransforms != NULL)
            {
                objRenderFn_80041018(obj);
            }
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & STAYPOINT_HITBOX_IN_RANGE) != 0)
            {
                ((void (*)(void*, int, int, int))(*(int*)(*(int*)(*(int*)((int)tricky + 0x68)) + 0x28)))(
                    tricky, obj, 1, 3);
            }
        }
    }
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
