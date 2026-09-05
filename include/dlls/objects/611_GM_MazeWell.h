#ifndef DLLS_OBJECTS_611_GM_MAZEWELL_H_
#define DLLS_OBJECTS_611_GM_MAZEWELL_H_

#include "game/objects/object.h"
#include "global.h"
#include "main/objseq.h"
#include "dlls/object_descriptor.h"

typedef struct GmmazewellState {
    u8 unk0;             /* 0x00: cleared at init, never read */
    u8 savepointSet;     /* 0x01: savepoint stamped once player object is available */
    u8 pad2[2];          /* 0x02 */
    s32 pendingDialogue; /* 0x04: dialogue id queued for the next event 1 (-1 = none) */
} GmmazewellState;

STATIC_ASSERT(offsetof(GmmazewellState, pendingDialogue) == 0x4);
STATIC_ASSERT(sizeof(GmmazewellState) == 0x8);

int GM_MazeWell_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
int GM_MazeWell_getExtraSize(void);
void GM_MazeWell_free(void);
void GM_MazeWell_render(void* obj, int p2, int p3, int p4, int p5, s8 visible);
void GM_MazeWell_update(GameObject* obj);
void GM_MazeWell_init(GameObject* obj);

extern s16 gGmMazeWellQuestBits[];
extern ObjectDescriptor gGmMazeWellObjDescriptor;

#endif /* DLLS_OBJECTS_611_GM_MAZEWELL_H_ */
