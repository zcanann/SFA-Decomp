#ifndef MAIN_DLL_DLL_0106_SCARAB_H_
#define MAIN_DLL_DLL_0106_SCARAB_H_

#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/obj_placement.h"
#include "main/frustum.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/objhits.h"

/* Crate spawners allocate 0x24 bytes for scarab setup records and initialize
   the lifetime at 0x1A before passing the common placement head to the object
   constructor. */
typedef struct ScarabPlacement {
    ObjPlacement base;    /* 0x00 */
    u8 unk18[2];
    s16 activeTimer;      /* 0x1A active lifetime in frames */
    u8 unk1C[0x24 - 0x1C];
} ScarabPlacement;

STATIC_ASSERT(offsetof(ScarabPlacement, activeTimer) == 0x1A);
STATIC_ASSERT(sizeof(ScarabPlacement) == 0x24);

int scarab_sweptCollide(GameObject* obj);
int Scarab_getExtraSize(void);
void Scarab_free(void);
void Scarab_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void Scarab_update(GameObject* obj);
void Scarab_init(GameObject* obj, ScarabPlacement* placement);

#endif
