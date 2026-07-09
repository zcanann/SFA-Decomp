#ifndef MAIN_DLL_DLL_0263_GMMAZEWELL_H_
#define MAIN_DLL_DLL_0263_GMMAZEWELL_H_

#include "main/game_object.h"
#include "global.h"
#include "main/objanim_update.h"

typedef struct GmmazewellState
{
    u8 unk0;             /* 0x00: cleared at init, never read */
    u8 savepointSet;     /* 0x01: savepoint stamped once player object is available */
    u8 pad2[2];          /* 0x02 */
    s32 pendingDialogue; /* 0x04: dialogue id queued for the next event 1 (-1 = none) */
} GmmazewellState;

STATIC_ASSERT(offsetof(GmmazewellState, pendingDialogue) == 0x4);
STATIC_ASSERT(sizeof(GmmazewellState) == 0x8);

int GM_MazeWell_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int GM_MazeWell_getExtraSize(void);
void GM_MazeWell_free(void);
void GM_MazeWell_render(void* obj, int p2, int p3, int p4, int p5, s8 visible);
void GM_MazeWell_update(unsigned int obj);
void GM_MazeWell_init(GameObject* obj);

#endif /* MAIN_DLL_DLL_0263_GMMAZEWELL_H_ */
