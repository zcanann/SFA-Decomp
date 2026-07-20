/*
 * dimbarrier (DLL 0x1C5) - barrier object for Dinosaur Island Mission.
 * While a live type-470 object is in the trigger list, counts down an arm
 * timer; on expiry fades the barrier out and latches its gamebit.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/audio/sfx.h"

#define DIMBARRIER_TRIGGER_SEQ_ID 470

/* dimbarrier_update state machine */
#define DIMBARRIER_STATE_ARMED 0    /* watching the trigger list, counting down */
#define DIMBARRIER_STATE_FADING 1   /* fading alpha out before latching the gamebit */
#define DIMBARRIER_STATE_RESOLVED 2 /* faded away, gamebit latched */

typedef struct DimbarrierPlacement
{
    ObjPlacement head;
    s8 rotX;
    u8 pad19[0x1E - 0x19];
    s16 barrierGameBit;
} DimbarrierPlacement;

typedef struct DimbarrierState
{
    s16 timer;
    u8 state;
    s8 countdown;
} DimbarrierState;

typedef struct DimbarrierTriggerState
{
    u8 pad0[4];
    u8 active;
} DimbarrierTriggerState;

STATIC_ASSERT(offsetof(DimbarrierPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(DimbarrierPlacement, barrierGameBit) == 0x1E);
STATIC_ASSERT(sizeof(DimbarrierState) == 0x4);
STATIC_ASSERT(offsetof(DimbarrierTriggerState, active) == 0x4);


int dimbarrier_getExtraSize(void) { return sizeof(DimbarrierState); }
int dimbarrier_getObjectTypeId(void) { return 0x0; }

void dimbarrier_free(void)
{
}

void dimbarrier_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dimbarrier_hitDetect(void)
{
}

void dimbarrier_update(GameObject* obj)
{
    DimbarrierPlacement* placement = (DimbarrierPlacement*)obj->anim.placementData;
    DimbarrierState* state = obj->extra;
    switch (state->state)
    {
    case DIMBARRIER_STATE_ARMED:
        {
            GameObject* entry;
            DimbarrierTriggerState* triggerState;
            int found;
            int i;
            found = 0;
            for (i = 0; i < obj->anim.proximityList->count; i++)
            {
                entry = obj->anim.proximityList->objects[i];
                triggerState = entry->extra;
                if (entry->anim.seqId == DIMBARRIER_TRIGGER_SEQ_ID && triggerState->active != 0)
                {
                    found = 1;
                    break;
                }
            }
            if (found)
            {
                if (--state->countdown <= 0)
                {
                    state->state = DIMBARRIER_STATE_FADING;
                    state->timer = 30;
                    Sfx_PlayFromObject((int)obj, SFXTRIG_wp_dsmk2_c_206);
                }
                else
                {
                    Sfx_PlayFromObject((int)obj, SFXTRIG_wp_dsmk2_c_207);
                }
            }
            break;
        }
    case DIMBARRIER_STATE_FADING:
        {
            ObjHitsPriorityState* hitState;
            int v = obj->anim.alpha - framesThisStep * 16;
            if (v < 0)
            {
                v = 0;
            }
            hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            obj->anim.alpha = v;
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(placement->barrierGameBit, 1);
                state->state = DIMBARRIER_STATE_RESOLVED;
            }
            break;
        }
    case DIMBARRIER_STATE_RESOLVED:
        break;
    }
}

void dimbarrier_init(GameObject* obj, DimbarrierPlacement* placement)
{
    DimbarrierState* state;
    obj->anim.rotX = (s16)((s32)placement->rotX << 8);
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    state = obj->extra;
    state->countdown = 1;
    state->state = DIMBARRIER_STATE_ARMED;
    if (mainGetBit(placement->barrierGameBit) != 0)
    {
        ObjHitsPriorityState* hitState;
        state->countdown = 0;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        obj->anim.alpha = 0;
        state->state = DIMBARRIER_STATE_RESOLVED;
    }
}

void dimbarrier_release(void)
{
}

void dimbarrier_initialise(void)
{
}

ObjectDescriptor gDIMBarrierObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimbarrier_initialise,
    (ObjectDescriptorCallback)dimbarrier_release,
    0,
    (ObjectDescriptorCallback)dimbarrier_init,
    (ObjectDescriptorCallback)dimbarrier_update,
    (ObjectDescriptorCallback)dimbarrier_hitDetect,
    (ObjectDescriptorCallback)dimbarrier_render,
    (ObjectDescriptorCallback)dimbarrier_free,
    (ObjectDescriptorCallback)dimbarrier_getObjectTypeId,
    dimbarrier_getExtraSize,
};
