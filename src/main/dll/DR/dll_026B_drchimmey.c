/*
 * drchimmey (DLL 0x26B) - a chimney/altar that accepts a number of
 * offerings. Each Tricky interaction decrements offeringsRemaining
 * (drchimmey_countdownCallback); once it reaches zero the event fires,
 * the completion game bit is set and a countdown timer resets the
 * altar back to its idle state.
 */
#include "main/objprint_render_api.h"
#include "main/gamebits.h"
#include "main/object.h"
#include "main/maketex_timer_api.h"
#include "main/obj_placement.h"
#include "main/object_render.h"
#include "main/dll/DR/dll_026B_drchimmey.h"

__declspec(section ".sdata2") f32 lbl_803E69E0 = 1.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E69E4 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E69E8 = 90.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E69EC = 0.0f;
#pragma explicit_zero_data off

int drchimmey_countdownCallback(DRChimmeyObject* obj, int amount)
{
    DRChimmeyState* state = obj->state;
    state->offeringsRemaining -= amount;
    return state->offeringsRemaining <= 0;
}

int DR_Chimmey_getExtraSize(void)
{
    return 0x18;
}

void DR_Chimmey_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumesFwdDoubleLegacy(obj, p2, p3, p4, p5, (double)lbl_803E69E0);
    }
}

void DR_Chimmey_update(DRChimmeyObject* obj)
{
    DRChimmeySetup* setup = obj->setup;
    DRChimmeyState* state = obj->state;

    obj->renderFlags |= 8;
    if (setup->enableGameBit != -1 && mainGetBit(setup->enableGameBit) == 0)
    {
        return;
    }
    if (fn_80080150(&state->timer) == 0)
    {
        if (state->offeringsRemaining <= 0)
        {
            state->eventActive = 1;
            s16toFloat(&state->timer, state->timerDuration);
            mainSetBits(state->completionGameBit, 1);
        }
        else
        {
            int* tricky = (int*)getTrickyObject();
            if (tricky != 0)
            {
                if ((obj->renderFlags & 4) != 0)
                {
                    (*(void (**)(int*, int, int, int))((char*)*(void**)*(void**)((char*)tricky + 0x68) + 0x28))(
                        tricky, (int)obj, 1, 4);
                }
                obj->renderFlags &= ~8;
                objRenderFn_80041018((GameObject*)obj);
            }
        }
    }
    if (timerCountDown(&state->timer) != 0)
    {
        state->linkedObject = NULL;
        state->timer = lbl_803E69E4;
        state->eventActive = 0;
        state->offeringsRemaining = 1;
        mainSetBits(state->completionGameBit, 0);
        mainSetBits(0xea4, 0);
    }
}

void DR_Chimmey_init(DRChimmeyObject* obj, DRChimmeySetup* setup)
{
    DRChimmeyState* state;

    obj->yaw = (s16)(setup->yawByte << 8);
    state = obj->state;
    state->timerDuration = lbl_803E69E8;
    state->completionGameBit = setup->completionGameBit;
    state->offeringsRemaining = 3;
    storeZeroToFloatParam(&state->timer);
}
