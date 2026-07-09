/*
 * cntcounter (DLL 0x2B4) - a generic countdown object.
 * Reads an initial count and two game bits from placement data: one bit
 * that, when set, decrements the counter (the bit's value is used as the
 * decrement amount and then cleared), and one bit set when the counter
 * reaches zero. Optionally shows the current count on the HUD.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/cntcounter_state.h"

typedef struct CntCounterSetup
{
    ObjPlacement base;
    u8 pad18;
    u8 displayHud;
    s16 initialCount;
    s16 pad1C;
    s16 doneGameBit;
    s16 decrementGameBit;
} CntCounterSetup;

STATIC_ASSERT(offsetof(CntCounterSetup, displayHud) == 0x19);
STATIC_ASSERT(offsetof(CntCounterSetup, initialCount) == 0x1A);
STATIC_ASSERT(offsetof(CntCounterSetup, doneGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CntCounterSetup, decrementGameBit) == 0x20);
STATIC_ASSERT(sizeof(CntCounterSetup) == 0x24);

int CntCounter_getExtraSize(void)
{
    return 8;
}

int CntCounter_getObjectTypeId(void)
{
    return 0;
}

void CntCounter_free(struct GameObject *obj)
{
    CntCounterState* state = (obj)->extra;
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

void CntCounter_update(struct GameObject *obj)
{
    CntCounterState* state = (obj)->extra;
    CntCounterSetup* setup = (CntCounterSetup*)(obj)->anim.placementData;

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

void CntCounter_init(struct GameObject *obj)
{
    CntCounterState* state = (obj)->extra;
    state->displayHud = 0;
    state->remainingCount = 0;
}

void CntCounter_release(void)
{
}

void CntCounter_initialise(void)
{
}
