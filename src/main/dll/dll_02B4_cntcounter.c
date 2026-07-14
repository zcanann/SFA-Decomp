/*
 * cntcounter (DLL 0x2B4) - a generic countdown object.
 * Reads an initial count and two game bits from placement data: one bit
 * that, when set, decrements the counter (the bit's value is used as the
 * decrement amount and then cleared), and one bit set when the counter
 * reaches zero. Optionally shows the current count on the HUD.
 */
#include "main/dll/dll_02B4_cntcounter.h"
#include "main/gamebits.h"
#include "main/model_engine.h"
#include "main/object_descriptor.h"

int CntCounter_getExtraSize(void)
{
    return 8;
}

int CntCounter_getObjectTypeId(void)
{
    return 0;
}

void CntCounter_free(GameObject* obj)
{
    CntCounterState* state = obj->extra;
    if (state->displayHud != 0)
    {
        set_hudNumber_803db278(-1);
    }
}

void CntCounter_render(void)
{
}

void CntCounter_hitDetect(void)
{
}

void CntCounter_update(GameObject* obj)
{
    CntCounterState* state = obj->extra;
    CntCounterSetup* setup = (CntCounterSetup*)obj->anim.placementData;

    if (state->remainingCount != 0)
    {
        int bit;
        if (state->displayHud != 0)
        {
            set_hudNumber_803db278(state->remainingCount);
        }
        bit = mainGetBit(setup->decrementGameBit);
        if (bit != 0)
        {
            mainSetBits(setup->decrementGameBit, 0);
            state->remainingCount -= bit;
            if (state->remainingCount <= 0)
            {
                state->remainingCount = 0;
                mainSetBits(setup->doneGameBit, 1);
                if (state->displayHud != 0)
                {
                    set_hudNumber_803db278(-1);
                }
                state->displayHud = 0;
            }
        }
    }
    else
    {
        if ((u32)mainGetBit(setup->decrementGameBit) != 0)
        {
            state->displayHud = setup->displayHud;
            state->remainingCount = setup->initialCount;
        }
    }
}

void CntCounter_init(GameObject* obj)
{
    CntCounterState* state = obj->extra;
    state->displayHud = 0;
    state->remainingCount = 0;
}

void CntCounter_release(void)
{
}

void CntCounter_initialise(void)
{
}

ObjectDescriptor gCNTcounterObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)CntCounter_initialise,
    (ObjectDescriptorCallback)CntCounter_release,
    0,
    (ObjectDescriptorCallback)CntCounter_init,
    (ObjectDescriptorCallback)CntCounter_update,
    (ObjectDescriptorCallback)CntCounter_hitDetect,
    (ObjectDescriptorCallback)CntCounter_render,
    (ObjectDescriptorCallback)CntCounter_free,
    (ObjectDescriptorCallback)CntCounter_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)CntCounter_getExtraSize,
};
