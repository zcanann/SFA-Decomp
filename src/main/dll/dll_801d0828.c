#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/dll/projball1D8.h"
#include "main/objseq.h"

extern uint GameBit_Get();

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

int EdibleMushroom_SeqFn(int* obj)
{
    *(u8*)(*(int*)&((GameObject*)obj)->extra + 0x139) = 1;
    return 0;
}

extern uint GameBit_Get(int id);

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
