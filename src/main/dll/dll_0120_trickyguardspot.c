/* DLL 0x0120 (trickyguardspot) — Tricky guard spot object. */

#include "main/dll/dll_0120_trickyguardspot.h"
#include "main/frame_timing.h"
#include "main/vecmath_distance_api.h"
#include "main/objprint_render_api.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/object_descriptor.h"

int TrickyGuardSpot_getExtraSize(void) { return 0x8; }

void TrickyGuardSpot_free(TrickyGuardSpotObject* obj) { ObjGroup_RemoveObject((int)obj, TRICKY_GUARD_SPOT_GROUP); }

void TrickyGuardSpot_render(void)
{
}

#define TRICKY_GUARD_SPOT_VTABLE(tricky) \
    (*(TrickyGuardSpotInterfaceVTable **)((tricky)->dll))

void TrickyGuardSpot_update(TrickyGuardSpotObject* obj)
{

    u8* state;
    u8* placement;
    ObjAnimComponent* tricky;
    TrickyGuardSpotStateFlags* flags;

    state = ((GameObject*)obj)->extra;
    placement = *(u8**)&((GameObject*)obj)->anim.placementData;
    tricky = (ObjAnimComponent*)getTrickyObject();
    flags = (TrickyGuardSpotStateFlags*)(state + 4);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG);
    flags->trickyInRange = 0;
    if (tricky != NULL)
    {
        if ((u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(tricky) != 0)
        {
            if (Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX,
                               (f32*)((char*)tricky + 0x18)) < (f32)(s32)((TrickyGuardSpotPlacement*)placement)->triggerRadius)
            {
                *(int*)state = *(int*)state - framesThisStep;
                flags->trickyInRange = 1;
            }
        }
    }
    if (*(u32*)state != 0)
    {
        if (tricky != NULL && (u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(tricky) == 0)
        {
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & TRICKY_GUARD_SPOT_VISIBLE_HITBOX_FLAG) != 0)
            {
                TRICKY_GUARD_SPOT_VTABLE(tricky)->setGuardSpotAction(
                    tricky, obj, TRICKY_GUARD_SPOT_ACTION, TRICKY_GUARD_SPOT_ACTION_PARAM);
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
                (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG);
            objRenderFn_80041018((GameObject*)obj);
        }
    }
    else if (tricky != NULL)
    {
        TRICKY_GUARD_SPOT_VTABLE(tricky)->resetGuardSpotAction(tricky);
        *(int*)state = placement[0x19] * 0x3c;
    }
    mainSetBits(((TrickyGuardSpotPlacement*)placement)->rangeGameBit, flags->trickyInRange);
}

void TrickyGuardSpot_init(TrickyGuardSpotObject* obj, TrickyGuardSpotPlacement* def)
{
    TrickyGuardSpotState* state = obj->state;
    ObjGroup_AddObject((int)obj, TRICKY_GUARD_SPOT_GROUP);
    state->resetTimer = def->resetSeconds * 60;
    obj->objAnim.rotX = (s16)(s32)
    def->initialYaw;
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
