#ifndef MAIN_DLL_SEQOBJ11E_H_
#define MAIN_DLL_SEQOBJ11E_H_

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/baddie_state.h"
#include "main/objtexture.h"
#include "main/gameplay_runtime.h"

/*
 * Setup buffer fn_80152370 fills for a spawned child object (0x24 bytes from
 * Obj_AllocObjectSetup). Embeds the common ObjPlacement head; the class byte at
 * 0x18 is left unwritten and 0x19 / 0x20 carry class-specific slots this handler
 * seeds. Names beyond the head are generic (provenance is the raw store offsets).
 */
typedef struct Seq11EChildSetup {
    ObjPlacement head;      /* 0x00: common placement head (type id also stored at +0x00) */
    u8 pad18;               /* 0x18: class byte (unwritten here) */
    u8 unk19;               /* 0x19 */
    u8 pad1A[0x20 - 0x1A];  /* 0x1A */
    s16 unk20;              /* 0x20 */
    u8 pad22[0x24 - 0x22];  /* 0x22 */
} Seq11EChildSetup;

STATIC_ASSERT(offsetof(Seq11EChildSetup, unk19) == 0x19);
STATIC_ASSERT(offsetof(Seq11EChildSetup, unk20) == 0x20);
STATIC_ASSERT(sizeof(Seq11EChildSetup) == 0x24);

int fn_80152370(int obj, int p2);

#endif
