/*
 * CNTcounter (DLL 692) is a game-bit-driven counter. A nonzero input starts
 * an idle counter without clearing that input. A later active update consumes
 * the input's value as a decrement and clears it. Reaching zero sets the done
 * game bit; initialization and restarting do not reset that completion bit.
 * The optional shared HUD number is written before consuming the decrement.
 */
#include "dlls/objects/692_CNTcounter.h"
#include "game/objects/object.h"
#include "main/gamebits.h"
#include "main/model_engine.h"

int CntCounter_getExtraSize(void)
{
    return sizeof(CntCounterState);
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
        hudNumberSet(-1);
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
    CntCounterPlacementPrefix* setup = (CntCounterPlacementPrefix*)obj->anim.placementData;

    if (state->remainingCount != 0)
    {
        int decrementAmount;
        if (state->displayHud != 0)
        {
            hudNumberSet(state->remainingCount);
        }
        decrementAmount = mainGetBit(setup->countInputGameBit);
        if (decrementAmount != 0)
        {
            mainSetBits(setup->countInputGameBit, 0);
            state->remainingCount -= decrementAmount;
            if (state->remainingCount <= 0)
            {
                state->remainingCount = 0;
                mainSetBits(setup->doneGameBit, 1);
                if (state->displayHud != 0)
                {
                    hudNumberSet(-1);
                }
                state->displayHud = 0;
            }
        }
    }
    else
    {
        if (mainGetBit(setup->countInputGameBit) != 0)
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
    CntCounter_initialise,
    CntCounter_release,
    0,
    (ObjectDescriptorCallback)CntCounter_init,
    (ObjectDescriptorCallback)CntCounter_update,
    CntCounter_hitDetect,
    CntCounter_render,
    (ObjectDescriptorCallback)CntCounter_free,
    (ObjectDescriptorCallback)CntCounter_getObjectTypeId,
    CntCounter_getExtraSize,
};
