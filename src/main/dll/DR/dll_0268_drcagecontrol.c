/*
 * drcagecontrol (DLL 0x268) - drives a cage that opens in response to
 * game bits. The placement supplies the game bit that arms the cage
 * and the bit watched by the trigger callback to play the pickup sfx
 * and report completion.
 *
 * The runtime record holds the active sequence id and status flags for
 * the watched bit, sequence startup, and the initially-armed path.
 */
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/DR/dll_0268_drcagecontrol.h"
#include "main/object_descriptor.h"


int DR_CageControl_SeqFn(GameObject* obj)
{
    int ret;
    CageControlPlacement* placement = (CageControlPlacement*)obj->anim.placementData;
    DRCageControlState* state = obj->extra;
    if (state->sequenceId == 0)
    {
        if (mainGetBit(placement->armGameBit) != 0)
        {
            Sfx_StopObjectChannel((int)obj, 8);
            return 4;
        }
        if (state->flags.watchBitSet != mainGetBit(placement->watchGameBit))
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_mv_blkhit_c);
            Sfx_PlayFromObject((int)obj, SFXTRIG_mv_persquk2);
            if (mainGetBit(placement->watchGameBit) != 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_mv_wickpickup16_194);
            }
            else
            {
                Sfx_StopObjectChannel((int)obj, 8);
            }
        }
        state->flags.watchBitSet = mainGetBit(placement->watchGameBit);
    }
    ret = 0;
    if (state->sequenceId == 0)
    {
        if (mainGetBit(placement->watchGameBit) == 0)
        {
            ret = 1;
        }
    }
    return ret;
}

int DR_CageControl_getExtraSize(void)
{
    return 0x4;
}

int DR_CageControl_getObjectTypeId(void)
{
    return 0x0;
}

void DR_CageControl_free(void)
{
}

void DR_CageControl_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, s8 visible)
{
    if (visible != 0)
    {
        f32 scale = 1.0f;
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, scale);
    }
}

void DR_CageControl_hitDetect(void)
{
}

void DR_CageControl_update(GameObject* obj)
{
    CageControlPlacement* placement = (CageControlPlacement*)obj->anim.placementData;
    DRCageControlState* state = obj->extra;
    if (state->flags.sequenceStarted != 0)
    {
        return;
    }
    if (state->sequenceId == 0 && mainGetBit(placement->armGameBit) != 0)
    {
        state->flags.sequenceStarted = 1;
        state->sequenceId = 2;
    }
    if (state->flags.initiallyArmed != 0)
    {
        state->flags.sequenceStarted = 1;
        (*gObjectTriggerInterface)->preempt((int)obj, 0x76c);
        if (mainGetBit(GAMEBIT_DR_EnteredDrakorTower) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, 0x60);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, 0x70);
        }
    }
    else
    {
        (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
    }
}

void DR_CageControl_init(GameObject* obj, CageControlPlacement* placement)
{
    DRCageControlState* state = obj->extra;
    obj->animEventCallback = DR_CageControl_SeqFn;
    if (mainGetBit(placement->armGameBit) != 0)
    {
        state->flags.initiallyArmed = 1;
        state->sequenceId = 2;
    }
    else
    {
        state->sequenceId = 0;
    }
}

void DR_CageControl_release(void)
{
}

void DR_CageControl_initialise(void)
{
}

ObjectDescriptor gDrCageControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DR_CageControl_initialise,
    (ObjectDescriptorCallback)DR_CageControl_release,
    0,
    (ObjectDescriptorCallback)DR_CageControl_init,
    (ObjectDescriptorCallback)DR_CageControl_update,
    (ObjectDescriptorCallback)DR_CageControl_hitDetect,
    (ObjectDescriptorCallback)DR_CageControl_render,
    (ObjectDescriptorCallback)DR_CageControl_free,
    (ObjectDescriptorCallback)DR_CageControl_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)DR_CageControl_getExtraSize,
};
