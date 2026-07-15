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
 * extra block (ColdWaterControl_getExtraSize = 8 bytes):
 *   0x00 f32  immersion timer
 *   0x04 ptr  cached player object (Obj_GetPlayerObject)
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0119_coldwatercontrol.h"
#include "main/dll/player_api.h"

#define GAMEBIT_COLDWATER_ARM  0x1bf
#define GAMEBIT_COLDWATER_DONE 0x1bd

#define COLDWATER_HIT_PRIORITY 0x1c

#define COLDWATER_OBJFLAG_HIDDEN             0x4000
#define COLDWATER_OBJFLAG_HITDETECT_DISABLED 0x2000

int ColdWaterControl_getExtraSize(void)
{
    return 0x8;
}

#pragma scheduling off
#pragma peephole off
void ColdWaterControl_update(GameObject* obj)
{
    ColdwaterControlState* state;

    state = (obj)->extra;
    if (mainGetBit(GAMEBIT_COLDWATER_ARM) != 0 && mainGetBit(GAMEBIT_COLDWATER_DONE) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        mainSetBits(GAMEBIT_COLDWATER_DONE, 1);
        return;
    }

    if (state->playerObj != NULL)
    {
        if (fn_80295C40(state->playerObj) != 0)
        {
            if (-30.0f == state->timer)
            {
                ObjHits_RecordObjectHit((int)state->playerObj, (int)obj, COLDWATER_HIT_PRIORITY, 0, 1);
            }

            state->timer = state->timer + timeDelta;
            if (state->timer > 240.0f)
            {
                ObjHits_RecordObjectHit((int)state->playerObj, (int)obj, COLDWATER_HIT_PRIORITY, 1, 1);
                state->timer = state->timer - 240.0f;
            }
        }
        else
        {
            state->timer = -30.0f;
        }
    }
    else
    {
        state->playerObj = Obj_GetPlayerObject();
    }
}

#pragma scheduling on
void ColdWaterControl_init(GameObject* obj)
{
    ColdwaterControlState* p = (ColdwaterControlState*)obj->extra;
    p->timer = -30.0f;
    obj->objectFlags = (u16)(obj->objectFlags | (COLDWATER_OBJFLAG_HIDDEN | COLDWATER_OBJFLAG_HITDETECT_DISABLED));
}
