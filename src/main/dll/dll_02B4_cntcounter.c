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

int cntcounter_getExtraSize(void) { return 8; }

int cntcounter_getObjectTypeId(void) { return 0; }

void cntcounter_free(int obj)
{
    CntCounterState* state = ((GameObject*)obj)->extra;
    if (state->displayHud != 0)
    {
        set_hudNumber_803db278(-1);
    }
}

void cntcounter_hitDetect(void)
{
}

void cntcounter_render(void)
{
}

void cntcounter_init(int obj)
{
    CntCounterState* state = ((GameObject*)obj)->extra;
    state->displayHud = 0;
    state->remainingCount = 0;
}

void cntcounter_update(int obj)
{
    CntCounterState* state = ((GameObject*)obj)->extra;
    CntCounterSetup* setup = (CntCounterSetup*)((GameObject*)obj)->anim.placementData;

    if (state->remainingCount != 0)
    {
        int bit;
        if (state->displayHud != 0)
        {
            set_hudNumber_803db278(state->remainingCount);
        }
        bit = GameBit_Get(setup->decrementGameBit);
        if (bit != 0)
        {
            GameBit_Set(setup->decrementGameBit, 0);
            state->remainingCount -= bit;
            if (state->remainingCount <= 0)
            {
                state->remainingCount = 0;
                GameBit_Set(setup->doneGameBit, 1);
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
        if ((u32)GameBit_Get(setup->decrementGameBit) != 0)
        {
            state->displayHud = setup->displayHud;
            state->remainingCount = setup->initialCount;
        }
    }
}

void cntcounter_release(void)
{
}

void cntcounter_initialise(void)
{
}
