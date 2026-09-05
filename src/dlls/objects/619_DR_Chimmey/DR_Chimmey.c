/*
 * DR_Chimmey (DLL 619) - a chimney/altar that accepts a number of
 * offerings. Each Tricky interaction decrements offeringsRemaining
 * (drchimmey_countdownCallback); once it reaches zero the event fires,
 * the completion game bit is set and a countdown timer resets the
 * altar back to its idle state.
 */
#include "main/gamebits.h"
#include "sys/objects/lifecycle.h"
#include "main/maketex_timer_api.h"
#include "main/object_render.h"
#include "main/dll/DR/dll_026B_drchimmey.h"
#include "dlls/objects/196_Tricky.h"
#include "main/objprint_render_api.h"

#define DRCHIMMEY_INITIAL_OFFERING_COUNT 3
#define DRCHIMMEY_REPEAT_OFFERING_COUNT  1
#define DRCHIMMEY_EVENT_DURATION         90.0f
#define DRCHIMMEY_RESET_GAMEBIT          0xEA4

int drchimmey_countdownCallback(GameObject* obj, int amount)
{
    DRChimmeyState* state = obj->extra;
    state->offeringsRemaining -= amount;
    return state->offeringsRemaining <= 0;
}

int DR_Chimmey_getExtraSize(void)
{
    return sizeof(DRChimmeyState);
}

void DR_Chimmey_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        f32 scale = 1.0f;
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, scale);
    }
}

void DR_Chimmey_update(GameObject* obj)
{
    DRChimmeySetup* setup = (DRChimmeySetup*)obj->anim.placementData;
    DRChimmeyState* state = obj->extra;

    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (setup->enableGameBit != -1 && mainGetBit(setup->enableGameBit) == 0)
    {
        return;
    }
    if (timerIsActive(&state->timer) == 0)
    {
        if (state->offeringsRemaining <= 0)
        {
            state->eventActive = 1;
            s16toFloat(&state->timer, state->timerDuration);
            mainSetBits(state->completionGameBit, 1);
        }
        else
        {
            GameObject* tricky = getTrickyObject();
            if (tricky != NULL)
            {
                if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
                {
                    TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                                               TRICKY_COMMAND_TYPE_FLAME);
                }
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                objUpdateHitVolumeTransforms(obj);
            }
        }
    }
    if (timerCountDown(&state->timer) != 0)
    {
        state->linkedObject = NULL;
        state->timer = 0.0f;
        state->eventActive = 0;
        state->offeringsRemaining = DRCHIMMEY_REPEAT_OFFERING_COUNT;
        mainSetBits(state->completionGameBit, 0);
        mainSetBits(DRCHIMMEY_RESET_GAMEBIT, 0);
    }
}

void DR_Chimmey_init(GameObject* obj, DRChimmeySetup* setup)
{
    DRChimmeyState* state;

    obj->anim.rotX = (s16)(setup->initialRotX << 8);
    state = obj->extra;
    state->timerDuration = DRCHIMMEY_EVENT_DURATION;
    state->completionGameBit = setup->completionGameBit;
    state->offeringsRemaining = DRCHIMMEY_INITIAL_OFFERING_COUNT;
    storeZeroToFloatParam(&state->timer);
}

ObjectDescriptor gDrChimmeyObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)DR_Chimmey_init,
    (ObjectDescriptorCallback)DR_Chimmey_update,
    0,
    (ObjectDescriptorCallback)DR_Chimmey_render,
    0,
    0,
    (ObjectDescriptorExtraSizeCallback)DR_Chimmey_getExtraSize,
};
