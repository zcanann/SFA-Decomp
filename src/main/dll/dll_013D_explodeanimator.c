/*
 * explodeanimator (DLL 0x13D) - one-shot particle burst animator.
 * When the trigger game bit (placement->triggerGameBit) becomes set, it fires
 * a configurable number of particles with randomised positions and velocities
 * drawn from per-axis min/max ranges in the placement data, then sets a result
 * game bit (placement->resultGameBit) and marks itself done (state->flags |= 1)
 * so it never fires again.
 *
 * Lives in OBJ_GROUP 0x1A alongside the sister xyzanimator (0x51) that drives
 * continuous map-geometry deformation.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/dll/dll_013D_explodeanimator.h"
#include "main/object_descriptor.h"

#define EXPLODEANIMATOR_OBJGROUP 0x1a
#define EXPLODEANIMATOR_FLAG_FIRED 0x1

int ExplodeAnimator_getExtraSize(void)
{
    return sizeof(ExplodeAnimatorState);
}
int ExplodeAnimator_getObjectTypeId(void)
{
    return 0x0;
}

void ExplodeAnimator_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, EXPLODEANIMATOR_OBJGROUP);
}

void ExplodeAnimator_render(void)
{
}

void ExplodeAnimator_hitDetect(void)
{
}

void ExplodeAnimator_update(GameObject* obj)
{
    int i;
    ExplodeAnimatorState* state;
    ExplodeAnimatorPlacement* placement;
    PartFxSpawnParams effect;
    f32 velocity[2];

    state = obj->extra;
    if ((state->flags & EXPLODEANIMATOR_FLAG_FIRED) != 0)
        return;
    placement = (ExplodeAnimatorPlacement*)obj->anim.placementData;
    if (mainGetBit(placement->triggerGameBit) == 0)
        return;
    mainSetBits(placement->resultGameBit, 1);
    state->flags = (u8)(state->flags | EXPLODEANIMATOR_FLAG_FIRED);
    {
        for (i = 0; i < placement->particleCount; i++)
        {
            velocity[0] = 0.01f * (f32)(s32)randomGetRange(placement->velXMin, placement->velXMax);
            velocity[1] = 0.01f * (f32)(s32)randomGetRange(placement->velYMin, placement->velYMax);
            effect.posX = (f32)(s32)randomGetRange(placement->posXMin, placement->posXMax);
            effect.posY = (f32)(s32)randomGetRange(placement->posYMin, placement->posYMax);
            effect.posZ = (f32)(s32)randomGetRange(placement->posZMin, placement->posZMax);
            (*gPartfxInterface)->spawnObject(obj, placement->effectId, &effect, 2, -1, velocity);
        }
    }
}

void ExplodeAnimator_init(GameObject* obj, ExplodeAnimatorPlacement* placement)
{
    ExplodeAnimatorState* state = obj->extra;
    int fired;
    if ((u32)mainGetBit(placement->resultGameBit) != 0u)
    {
        fired = 1;
    }
    else
    {
        fired = 0;
    }
    state->flags = fired;
    ObjGroup_AddObject((int)obj, EXPLODEANIMATOR_OBJGROUP);
}

void ExplodeAnimator_release(void)
{
}

void ExplodeAnimator_initialise(void)
{
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
