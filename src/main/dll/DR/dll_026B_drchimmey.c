/*
 * drchimmey (DLL 0x26B) - a chimney/altar that accepts a number of
 * offerings. Each Tricky interaction decrements offeringsRemaining
 * (drchimmey_countdownCallback); once it reaches zero the event fires,
 * the completion game bit is set and a countdown timer resets the
 * altar back to its idle state.
 */
#include "main/dll/DR/dr_shared.h"
#include "main/obj_placement.h"

typedef struct DRChimmeySetup
{
    ObjPlacement base;
    s8 yawByte;
    u8 pad19[5];
    s16 completionGameBit;
    s16 enableGameBit;
    u8 pad22[0x24 - 0x22];
} DRChimmeySetup;

typedef struct DRChimmeyState
{
    void* linkedObject;
    u8 pad04[8];
    f32 timerDuration;
    f32 timer;
    s16 completionGameBit;
    s8 offeringsRemaining;
    u8 eventActive;
} DRChimmeyState;

typedef struct DRChimmeyObject
{
    s16 yaw;
    u8 pad02[0x4a];
    DRChimmeySetup* setup;
    u8 pad50[0x5f];
    u8 renderFlags;
    u8 padB0[8];
    DRChimmeyState* state;
} DRChimmeyObject;

STATIC_ASSERT(sizeof(DRChimmeyState) == 0x18);
STATIC_ASSERT(offsetof(DRChimmeyState, timerDuration) == 0x0c);
STATIC_ASSERT(offsetof(DRChimmeyState, timer) == 0x10);
STATIC_ASSERT(offsetof(DRChimmeyState, completionGameBit) == 0x14);
STATIC_ASSERT(offsetof(DRChimmeyState, offeringsRemaining) == 0x16);
STATIC_ASSERT(offsetof(DRChimmeyState, eventActive) == 0x17);
STATIC_ASSERT(sizeof(DRChimmeySetup) == 0x24);
STATIC_ASSERT(offsetof(DRChimmeySetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(DRChimmeySetup, completionGameBit) == 0x1e);
STATIC_ASSERT(offsetof(DRChimmeySetup, enableGameBit) == 0x20);
STATIC_ASSERT(offsetof(DRChimmeyObject, setup) == 0x4c);
STATIC_ASSERT(offsetof(DRChimmeyObject, renderFlags) == 0xaf);
STATIC_ASSERT(offsetof(DRChimmeyObject, state) == 0xb8);

int drchimmey_getExtraSize(void) { return 0x18; }

void drchimmey_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E69E0);
    }
}

void drchimmey_init(DRChimmeyObject* obj, DRChimmeySetup* setup)
{
    DRChimmeyState* state;

    obj->yaw = (s16)(setup->yawByte << 8);
    state = obj->state;
    state->timerDuration = lbl_803E69E8;
    state->completionGameBit = setup->completionGameBit;
    state->offeringsRemaining = 3;
    storeZeroToFloatParam(&state->timer);
}

int drchimmey_countdownCallback(DRChimmeyObject* obj, int amount)
{
    DRChimmeyState* state = obj->state;
    state->offeringsRemaining -= amount;
    return state->offeringsRemaining <= 0;
}

void drchimmey_update(DRChimmeyObject* obj)
{
    DRChimmeySetup* setup = obj->setup;
    DRChimmeyState* state = obj->state;

    obj->renderFlags |= 8;
    if (setup->enableGameBit != -1 && GameBit_Get(setup->enableGameBit) == 0)
    {
        return;
    }
    if (fn_80080150(&state->timer) == 0)
    {
        if (state->offeringsRemaining <= 0)
        {
            state->eventActive = 1;
            s16toFloat(&state->timer, state->timerDuration);
            GameBit_Set(state->completionGameBit, 1);
        }
        else
        {
            int* tricky = getTrickyObject();
            if (tricky != 0)
            {
                if ((obj->renderFlags & 4) != 0)
                {
                    (*(void (**)(int*, int, int, int))((char*)*(void**)*(void**)((char*)tricky + 0x68) + 0x28))(
                        tricky, (int)obj, 1, 4);
                }
                obj->renderFlags &= ~8;
                objRenderFn_80041018((int)obj);
            }
        }
    }
    if (timerCountDown(&state->timer) != 0)
    {
        state->linkedObject = NULL;
        state->timer = lbl_803E69E4;
        state->eventActive = 0;
        state->offeringsRemaining = 1;
        GameBit_Set(state->completionGameBit, 0);
        GameBit_Set(0xea4, 0);
    }
}
