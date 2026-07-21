/*
 * visanimator (DLL 0x013A) - per-map-block visibility animator object.
 *
 * Its placement selects a game-bit value, one bit within that value, and the
 * initial map-block visibility state. The selected bit's current state XORs
 * visibilityBit, and each later transition toggles it again while the map
 * block containing the object remains loaded.
 */
#include "main/game_object.h"
#include "main/lightmap_api.h"
#include "main/gamebits.h"
#include "main/voxmaps.h"
#include "main/dll/dll_013A_visanimator.h"
#include "main/object_descriptor.h"

int VisAnimator_getExtraSize(void)
{
    return sizeof(VisAnimatorState);
}
int VisAnimator_getObjectTypeId(void)
{
    return 0x0;
}

void VisAnimator_free(void)
{
}

void VisAnimator_render(void)
{
}

void VisAnimator_hitDetect(void)
{
}

void VisAnimator_update(GameObject* obj)
{
    VisAnimatorPlacement* placement = (VisAnimatorPlacement*)obj->anim.placementData;
    VisAnimatorState* state = obj->extra;
    int idx =
        objPosToMapBlockIdx((double)obj->anim.localPosX, (double)obj->anim.localPosY,
                            (double)obj->anim.localPosZ);
    int gate;
    if (mapGetBlock(idx) == NULL)
    {
        state->flags |= VISANIMATOR_FLAG_REFRESH_PENDING;
        return;
    }
    gate = mainGetBit(placement->gateGameBit);
    state->currentGateState = (u8)(state->gateMask & gate);
    if (state->previousGateState != state->currentGateState)
    {
        state->visibilityBit = (s8)(state->visibilityBit ^ 1);
        state->flags |= VISANIMATOR_FLAG_REFRESH_PENDING;
    }
    state->previousGateState = state->currentGateState;
    if (state->flags & VISANIMATOR_FLAG_REFRESH_PENDING)
    {
        state->flags &= ~VISANIMATOR_FLAG_REFRESH_PENDING;
    }
}

void VisAnimator_init(GameObject* obj, VisAnimatorPlacement* placement)
{
    VisAnimatorState* state;
    u32 gate;
    u8 gateBit;
    int baseVisBit;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    state = obj->extra;
    baseVisBit = placement->initialVisibilityBit;
    state->visibilityBit = baseVisBit;
    state->gateMask = (u8)(1 << placement->gateBitIndex);
    gate = mainGetBit(placement->gateGameBit);
    if ((state->gateMask & gate) != 0)
    {
        state->visibilityBit = state->visibilityBit ^ 1;
    }
    mapGetBlock(objPosToMapBlockIdx((double)obj->anim.localPosX,
                                    (double)obj->anim.localPosY,
                                    (double)obj->anim.localPosZ));
    gate = mainGetBit(placement->gateGameBit);
    gateBit = (u8)(state->gateMask & gate);
    state->currentGateState = gateBit;
    state->previousGateState = gateBit;
    state->flags |= VISANIMATOR_FLAG_REFRESH_PENDING;
}

void VisAnimator_release(void)
{
}

void VisAnimator_initialise(void)
{
}

ObjectDescriptor gVisAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VisAnimator_initialise,
    (ObjectDescriptorCallback)VisAnimator_release,
    0,
    (ObjectDescriptorCallback)VisAnimator_init,
    (ObjectDescriptorCallback)VisAnimator_update,
    (ObjectDescriptorCallback)VisAnimator_hitDetect,
    (ObjectDescriptorCallback)VisAnimator_render,
    (ObjectDescriptorCallback)VisAnimator_free,
    (ObjectDescriptorCallback)VisAnimator_getObjectTypeId,
    VisAnimator_getExtraSize,
};
