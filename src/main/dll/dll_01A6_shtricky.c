#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/dll/projball1D8.h"
#include "main/objseq.h"


extern uint GameBit_Get();
extern undefined4 GameBit_Set();


/*
 * --INFO--
 *
 * Function: nw_levcontrol_update
 * EN v1.0 Address: 0x801CFF20
 * EN v1.0 Size: 1472b
 * EN v1.1 Address: 0x801D04F0
 * EN v1.1 Size: 1472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: sh_tricky_getExtraSize
 * EN v1.0 Address: 0x801D069C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int sh_tricky_getExtraSize(void)
{
    return 1;
}

extern int* getTrickyObject(void);

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

int EdibleMushroom_SeqFn(int* obj);

extern uint GameBit_Get(int id);

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
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
}

extern f32 lbl_803E5280;


/* === merged from main/dll/flybaddie1D7.c [801CFD68-801CFF20) (TU re-split, docs/boundary_audit.md) === */
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/game_object.h"
#include "main/objseq.h"



/*
 * --INFO--
 *
 * Function: fn_801CFD68
 * EN v1.0 Address: 0x801CFD68
 * EN v1.0 Size: 348b
 */

/*
 * --INFO--
 *
 * Function: nw_levcontrol_getExtraSize
 * EN v1.0 Address: 0x801CFEC4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* EN v1.0 0x801CFECC  size: 84b  nw_levcontrol_free: dispatches the object's
 * map event slot through gMapEventInterface; when the call returns 0 also fires
 * envFxActFn_800887f8(0); always tails into gameTimerStop. */
