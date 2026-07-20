/* DLL 0x0120 (trickyguardspot) - Tricky guard spot object. */

#include "main/dll/dll_0120_trickyguardspot.h"
#include "main/frame_timing.h"
#include "main/vecmath_distance_api.h"
#include "main/objprint_render_api.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/object_descriptor.h"

int TrickyGuardSpot_getExtraSize(void) { return sizeof(TrickyGuardSpotState); }

void TrickyGuardSpot_free(TrickyGuardSpotObject* obj) { ObjGroup_RemoveObject((int)obj, TRICKY_GUARD_SPOT_GROUP); }

void TrickyGuardSpot_render(void)
{
}

#define TRICKY_GUARD_SPOT_VTABLE(tricky) \
    (*(TrickyGuardSpotInterfaceVTable**)((tricky)->anim.dll))

void TrickyGuardSpot_update(TrickyGuardSpotObject* obj)
{

    TrickyGuardSpotState* state;
    TrickyGuardSpotPlacement* placement;
    GameObject* tricky;
    TrickyGuardSpotStateFlags* flags;

    state = obj->extra;
    placement = (TrickyGuardSpotPlacement*)obj->anim.placementData;
    tricky = getTrickyObject();
    flags = &state->flags;
    obj->anim.resetHitboxFlags =
        (u8)(obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
    flags->trickyInRange = 0;
    if (tricky != NULL)
    {
        if ((u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(&tricky->anim) != 0)
        {
            if (Vec_xzDistance(&obj->anim.worldPosX, &tricky->anim.worldPosX) <
                (f32)(s32)placement->triggerRadius)
            {
                state->resetTimer = state->resetTimer - framesThisStep;
                flags->trickyInRange = 1;
            }
        }
    }
    if (state->resetTimer != 0)
    {
        if (tricky != NULL &&
            (u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(&tricky->anim) == 0)
        {
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
            {
                TRICKY_GUARD_SPOT_VTABLE(tricky)->setGuardSpotAction(
                    &tricky->anim, obj, TRICKY_GUARD_SPOT_ACTION, TRICKY_GUARD_SPOT_ACTION_PARAM);
            }
            obj->anim.resetHitboxFlags =
                (u8)(obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
            objRenderFn_80041018(obj);
        }
    }
    else if (tricky != NULL)
    {
        TRICKY_GUARD_SPOT_VTABLE(tricky)->resetGuardSpotAction(&tricky->anim);
        state->resetTimer = placement->resetSeconds * 0x3c;
    }
    mainSetBits(placement->rangeGameBit, flags->trickyInRange);
}

void TrickyGuardSpot_init(TrickyGuardSpotObject* obj, TrickyGuardSpotPlacement* def)
{
    TrickyGuardSpotState* state = obj->extra;
    ObjGroup_AddObject((int)obj, TRICKY_GUARD_SPOT_GROUP);
    state->resetTimer = def->resetSeconds * 60;
    obj->anim.rotX = (s16)(s32)def->initialYaw;
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
