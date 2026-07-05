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
#include "main/dll/moonseedbushstate_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/dll/VF/vf_shared.h"
#include "main/object_descriptor.h"

#define MOONSEEDBUSH_OBJFLAG_HITDETECT_DISABLED 0x2000
extern f32 lbl_803E44D0;
extern f32 lbl_803E44D4;
extern f32 lbl_803E44D8;

typedef struct MoonSeedBushPlacement
{
    ObjPlacement base;
    s16 triggerGameBit; /* 0x18 */
    s16 grownGameBit;   /* 0x1A: seedState gamebit (-1 = none) */
    s16 preemptSeq;     /* 0x1C */
    s8 sequence;        /* 0x1E: sequence slot index (-1 = none) */
    u8 rotXByte;        /* 0x1F: rotX in 1/256 turns */
    u8 preemptSlot;     /* 0x20: preempt sequence slot */
    u8 scaleByte;       /* 0x21: model scale param */
    u8 pad22[0x28 - 0x22];
} MoonSeedBushPlacement;

/* sequence event opcodes consumed by MoonSeedBush_SeqFn */
#define MOONSEEDBUSH_SEQEV_PLANT 1
#define MOONSEEDBUSH_SEQEV_BURST_FX 2

/* seedState growth phases */
#define MOONSEEDBUSH_SEED_UNGROWN 0 /* dormant, watching trigger bit */
#define MOONSEEDBUSH_SEED_PLANTED 1 /* planted, growing */
#define MOONSEEDBUSH_SEED_GROWN   2 /* fully grown / triggered */

STATIC_ASSERT(sizeof(MoonSeedBushState) == 0x2);

void MoonSeedBush_free(void)
{
}

void MoonSeedBush_hitDetect(void)
{
}

void MoonSeedBush_release(void)
{
}

void MoonSeedBush_initialise(void)
{
}

int MoonSeedBush_getExtraSize(void) { return sizeof(MoonSeedBushState); }
int MoonSeedBush_getObjectTypeId(void) { return 0x0; }

#pragma peephole off
void MoonSeedBush_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E44D0);
}
#pragma reset

#pragma scheduling off
void MoonSeedBush_update(int obj)
{
    MoonSeedBushState* state = ((GameObject*)obj)->extra;
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    int preemptSlot;
    if ((state->flags & 1) == 0) return;
    if (((MoonSeedBushPlacement*)def)->preemptSeq != 0 && state->seedState != MOONSEEDBUSH_SEED_UNGROWN)
    {
        preemptSlot = ((MoonSeedBushPlacement*)def)->preemptSlot;
        (*gObjectTriggerInterface)->preempt(obj, ((MoonSeedBushPlacement*)def)->preemptSeq);
    }
    else
    {
        preemptSlot = -1;
    }
    {
        s32 idx = (s32)(s8) * (u8*)(def + 0x1E); /* placement->sequence */
        if (idx != -1)
        {
            (*gObjectTriggerInterface)->runSequence(idx, (void*)obj, preemptSlot);
        }
    }
    state->flags &= ~1;
}

int MoonSeedBush_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    MoonSeedBushState* state = ((GameObject*)obj)->extra;
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    int i;
    int j;
    if (state->seedState == MOONSEEDBUSH_SEED_UNGROWN)
    {
        if (GameBit_Get(((MoonSeedBushPlacement*)def)->triggerGameBit) != 0)
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
            if (((MoonSeedBushPlacement*)def)->grownGameBit != -1)
            {
                GameBit_Set(((MoonSeedBushPlacement*)def)->grownGameBit, 1);
            }
            break;
        case MOONSEEDBUSH_SEQEV_BURST_FX:
            (*gPartfxInterface)->spawnObject((void*)obj, 0x70B, NULL, 2, -1, NULL);
            for (j = 0; j < 0x28; j++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x70C, NULL, 2, -1, NULL);
            }
            break;
        }
    }
    return state->seedState != MOONSEEDBUSH_SEED_GROWN;
}

void MoonSeedBush_init(int obj, int data)
{
    MoonSeedBushState* state = ((GameObject*)obj)->extra;
    MoonSeedBushPlacement* placement = (MoonSeedBushPlacement*)data;
    state->flags = 1;
    ((GameObject*)obj)->anim.rotX = (s16)(placement->rotXByte << 8);
    ((GameObject*)obj)->animEventCallback = MoonSeedBush_SeqFn;
    ((GameObject*)obj)->objectFlags |= MOONSEEDBUSH_OBJFLAG_HITDETECT_DISABLED;
    ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)(placement->scaleByte) * lbl_803E44D4;
    if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E44D8)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E44D0;
    }
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    if (placement->grownGameBit != -1)
    {
        state->seedState = GameBit_Get(placement->grownGameBit);
    }
    else
    {
        state->seedState = MOONSEEDBUSH_SEED_UNGROWN;
    }
}
#pragma reset

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
