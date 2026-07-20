/*
 * DLL 0x17F - moonseedbush: a plantable "moon seed" bush spot.
 *
 * The spot watches its trigger game bit (placement->triggerGameBit);
 * once that bit is set the seed is considered grown (seedState 2). On
 * the first update tick (flags bit 0) it fires its placement-configured
 * trigger sequence (placement->sequence) - optionally pre-empted by
 * another sequence (placement->preemptSeq) when the seed has already
 * been planted - then clears the run-once flag.
 *
 * The sequence callback (MoonSeedBush_SeqFn) handles two anim events:
 *   1 = plant the seed (seedState 1, set placement->grownGameBit);
 *   2 = burst the seed particle fx (one 0x70B + 0x28 x 0x70C spawns).
 * SeqFn returns non-zero until the seed is fully grown.
 */
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"
#include "main/dll/dll_017F_moonseedbush.h"

STATIC_ASSERT(sizeof(MoonSeedBushState) == 0x2);

#define MOONSEEDBUSH_OBJFLAG_HITDETECT_DISABLED 0x2000

/* sequence event opcodes consumed by MoonSeedBush_SeqFn */
#define MOONSEEDBUSH_SEQEV_PLANT    1
#define MOONSEEDBUSH_SEQEV_BURST_FX 2

/* seed-burst particle fx: one lead burst + 0x28 spray spawns */
#define MOONSEEDBUSH_PARTFX_BURST 0x70B
#define MOONSEEDBUSH_PARTFX_SPRAY 0x70C

/* seedState growth phases */
#define MOONSEEDBUSH_SEED_UNGROWN 0 /* dormant, watching trigger bit */
#define MOONSEEDBUSH_SEED_PLANTED 1 /* planted, growing */
#define MOONSEEDBUSH_SEED_GROWN   2 /* fully grown / triggered */

int MoonSeedBush_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    MoonSeedBushState* state = obj->extra;
    MoonSeedBushPlacement* placement = (MoonSeedBushPlacement*)obj->anim.placementData;
    int i;
    int j;
    if (state->seedState == MOONSEEDBUSH_SEED_UNGROWN)
    {
        if (mainGetBit(placement->triggerGameBit) != 0)
        {
            state->seedState = MOONSEEDBUSH_SEED_GROWN;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch ((s32)animUpdate->eventIds[i])
        {
        case MOONSEEDBUSH_SEQEV_PLANT:
            state->seedState = MOONSEEDBUSH_SEED_PLANTED;
            if (placement->grownGameBit != -1)
            {
                mainSetBits(placement->grownGameBit, 1);
            }
            break;
        case MOONSEEDBUSH_SEQEV_BURST_FX:
            (*gPartfxInterface)->spawnObject((void*)obj, MOONSEEDBUSH_PARTFX_BURST, NULL, 2, -1, NULL);
            for (j = 0; j < 0x28; j++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, MOONSEEDBUSH_PARTFX_SPRAY, NULL, 2, -1, NULL);
            }
            break;
        }
    }
    return state->seedState != MOONSEEDBUSH_SEED_GROWN;
}

int MoonSeedBush_getExtraSize(void)
{
    return sizeof(MoonSeedBushState);
}
int MoonSeedBush_getObjectTypeId(void)
{
    return 0x0;
}

void MoonSeedBush_free(void)
{
}

void MoonSeedBush_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void MoonSeedBush_hitDetect(void)
{
}

void MoonSeedBush_update(GameObject* obj)
{
    MoonSeedBushState* state = obj->extra;
    MoonSeedBushPlacement* placement = (MoonSeedBushPlacement*)obj->anim.placementData;
    int preemptSlot;
    if ((state->flags & 1) == 0)
        return;
    if (placement->preemptSeq != 0 && state->seedState != MOONSEEDBUSH_SEED_UNGROWN)
    {
        preemptSlot = placement->preemptSlot;
        (*gObjectTriggerInterface)->preempt((int)obj, placement->preemptSeq);
    }
    else
    {
        preemptSlot = -1;
    }
    {
        u8 sequence = placement->sequence;
        s32 idx = (s8)sequence;
        if (idx != -1)
        {
            (*gObjectTriggerInterface)->runSequence(idx, (void*)obj, preemptSlot);
        }
    }
    state->flags &= ~1;
}

void MoonSeedBush_init(GameObject* obj, MoonSeedBushPlacement* placement)
{
    MoonSeedBushState* state = obj->extra;
    state->flags = 1;
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->animEventCallback = MoonSeedBush_SeqFn;
    obj->objectFlags |= MOONSEEDBUSH_OBJFLAG_HITDETECT_DISABLED;
    obj->anim.rootMotionScale = (f32)(u32)placement->scaleByte / 64.0f;
    if (!obj->anim.rootMotionScale)
    {
        obj->anim.rootMotionScale = 1.0f;
    }
    obj->anim.rootMotionScale = obj->anim.rootMotionScale * obj->anim.modelInstance->rootMotionScaleBase;
    if (placement->grownGameBit != -1)
    {
        state->seedState = mainGetBit(placement->grownGameBit);
    }
    else
    {
        state->seedState = MOONSEEDBUSH_SEED_UNGROWN;
    }
}

void MoonSeedBush_release(void)
{
}

void MoonSeedBush_initialise(void)
{
}

ObjectDescriptor gMoonSeedBushObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)MoonSeedBush_initialise,
    (ObjectDescriptorCallback)MoonSeedBush_release,
    0,
    (ObjectDescriptorCallback)MoonSeedBush_init,
    (ObjectDescriptorCallback)MoonSeedBush_update,
    (ObjectDescriptorCallback)MoonSeedBush_hitDetect,
    (ObjectDescriptorCallback)MoonSeedBush_render,
    (ObjectDescriptorCallback)MoonSeedBush_free,
    (ObjectDescriptorCallback)MoonSeedBush_getObjectTypeId,
    MoonSeedBush_getExtraSize,
};
