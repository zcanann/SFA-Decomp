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

#define SHTRICKY_STATE_WAIT_TRIGGER 0
#define SHTRICKY_STATE_HAND_CONTROL 1
#define SHTRICKY_STATE_POLL_TASK 2
#define SHTRICKY_STATE_WATCH_COMPLETE 3
#define SHTRICKY_STATE_DONE 4

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
    case SHTRICKY_STATE_WAIT_TRIGGER:
        if (GameBit_Get(0x94) != 0)
        {
            GameBit_Set(0x4e4, 0);
            GameBit_Set(0x4e5, 0);
            GameBit_Set(0xc11, 1);
            state[0] = SHTRICKY_STATE_HAND_CONTROL;
        }
        break;
    case SHTRICKY_STATE_HAND_CONTROL:
        state[0] = SHTRICKY_STATE_POLL_TASK;
        break;
    case SHTRICKY_STATE_POLL_TASK:
        if (((int (*)(int*, int*))(*(int*)(*(int*)(tricky[0x1a]) + 0x38)))(tricky, obj) !=
            0)
        {
            state[0] = SHTRICKY_STATE_WATCH_COMPLETE;
        }
        break;
    case SHTRICKY_STATE_WATCH_COMPLETE:
        if (GameBit_Get(0xbf) != 0)
        {
            GameBit_Set(0x4e4, 1);
            GameBit_Set(0x4e5, 1);
            GameBit_Set(0xc11, 0);
        }
        break;
    case SHTRICKY_STATE_DONE:
        break;
    }
}

void sh_tricky_init(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    if (GameBit_Get(0xbf) != 0)
    {
        *state = SHTRICKY_STATE_DONE;
    }
    else
    {
        *state = SHTRICKY_STATE_WAIT_TRIGGER;
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (SHTRICKY_OBJFLAG_HIDDEN | SHTRICKY_OBJFLAG_HITDETECT_DISABLED));
}
