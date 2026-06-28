/*
 * coldwatercontrol (DLL 0x119) - a cold-water damage trigger object.
 *
 * Once game bit 0x1bf is set (and 0x1bd not yet), it fires trigger
 * sequence 0 and latches 0x1bd so the sequence runs only once. After
 * that it tracks the player object: while the player passes the
 * fn_80295C40 gate it accumulates an immersion timer by timeDelta and
 * deals periodic ObjHits cold-water damage (priority 0x1c) - an entry
 * hit when the timer is fresh, then a repeating hit every lbl_803E3B6C
 * seconds. Failing the gate resets the timer to lbl_803E3B68.
 *
 * extra block (coldwatercontrol_getExtraSize = 8 bytes):
 *   0x00 f32  immersion timer
 *   0x04 ptr  cached player object (Obj_GetPlayerObject)
 */
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
extern int fn_80295C40(int obj);
extern f32 timeDelta;
extern f32 lbl_803E3B68; /* timer reset / initial value */
extern f32 lbl_803E3B6C; /* repeat-hit period */

#define GAMEBIT_COLDWATER_ARM 0x1bf
#define GAMEBIT_COLDWATER_DONE 0x1bd

#define COLDWATER_HIT_PRIORITY 0x1c

typedef struct ColdwaterControlState {
    f32 timer;       /* 0x00 immersion timer */
    void* playerObj; /* 0x04 cached player object */
} ColdwaterControlState;
STATIC_ASSERT(sizeof(ColdwaterControlState) == 0x8);
STATIC_ASSERT(offsetof(ColdwaterControlState, playerObj) == 0x4);

int coldwatercontrol_getExtraSize(void) { return 0x8; }

#pragma scheduling off
#pragma peephole off
void coldwatercontrol_update(int obj)
{
    ColdwaterControlState* state;

    state = ((GameObject*)obj)->extra;
    if (GameBit_Get(GAMEBIT_COLDWATER_ARM) != 0 && GameBit_Get(GAMEBIT_COLDWATER_DONE) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        GameBit_Set(GAMEBIT_COLDWATER_DONE, 1);
        return;
    }

    if (state->playerObj != NULL)
    {
        if (fn_80295C40((int)state->playerObj) != 0)
        {
            if (lbl_803E3B68 == state->timer)
            {
                ObjHits_RecordObjectHit((int)state->playerObj, obj, COLDWATER_HIT_PRIORITY, 0, 1);
            }

            state->timer = state->timer + timeDelta;
            if (state->timer > lbl_803E3B6C)
            {
                ObjHits_RecordObjectHit((int)state->playerObj, obj, COLDWATER_HIT_PRIORITY, 1, 1);
                state->timer = state->timer - lbl_803E3B6C;
            }
        }
        else
        {
            state->timer = lbl_803E3B68;
        }
    }
    else
    {
        state->playerObj = Obj_GetPlayerObject();
    }
}

#pragma scheduling on
void coldwatercontrol_init(int obj)
{
    ColdwaterControlState* p = (ColdwaterControlState*)((GameObject*)obj)->extra;
    p->timer = lbl_803E3B68;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
}
