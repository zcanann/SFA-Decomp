/*
 * shtricky (DLL 0x1A6) - SnowHorn-area scripted-state object that
 * watches Tricky's progress and toggles the related game bits.
 *
 * The single state byte (obj->extra[0]) drives a small sequence: it
 * waits on a trigger bit, hands control to Tricky, then polls a Tricky
 * vtable method until Tricky reports the task done, and finally watches
 * for the completion bit to flip the result bits back.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"

#define SHTRICKY_OBJFLAG_HIDDEN 0x4000
#define SHTRICKY_OBJFLAG_HITDETECT_DISABLED 0x2000

int sh_tricky_getExtraSize(void)
{
    return 1;
}

void sh_tricky_update(int* obj)
{
    u8* state;
    int* tricky;

    state = ((GameObject*)obj)->extra;
    tricky = getTrickyObject();
    if (tricky == NULL)
    {
        return;
    }

    switch (state[0])
    {
    case 0:
        if (GameBit_Get(0x94) != 0)
        {
            GameBit_Set(0x4e4, 0);
            GameBit_Set(0x4e5, 0);
            GameBit_Set(0xc11, 1);
            state[0] = 1;
        }
        break;
    case 1:
        state[0] = 2;
        break;
    case 2:
        if (((int (*)(int*, int*))(*(int*)(*(int*)(tricky[0x1a]) + 0x38)))(tricky, obj) !=
            0)
        {
            state[0] = 3;
        }
        break;
    case 3:
        if (GameBit_Get(0xbf) != 0)
        {
            GameBit_Set(0x4e4, 1);
            GameBit_Set(0x4e5, 1);
            GameBit_Set(0xc11, 0);
        }
        break;
    case 4:
        break;
    }
}

void sh_tricky_init(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    if (GameBit_Get(0xbf) != 0)
    {
        *state = 4;
    }
    else
    {
        *state = 0;
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (SHTRICKY_OBJFLAG_HIDDEN | SHTRICKY_OBJFLAG_HITDETECT_DISABLED));
}
