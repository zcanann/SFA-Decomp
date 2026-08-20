#ifndef MAIN_DLL_BADDIE_CHUKA_H_
#define MAIN_DLL_BADDIE_CHUKA_H_

#include "game/objects/object.h"
#include "types.h"
#include "global.h"

typedef struct ChukaState
{
    f32 startY;
    GameObject* levelController;
    u8 rowIndex;
    u8 safeTileIndex;
    u8 pad0A[2];
} ChukaState;

typedef struct ChukaPlacement ChukaPlacement;

STATIC_ASSERT(offsetof(ChukaState, levelController) == 0x4);
STATIC_ASSERT(sizeof(ChukaState) == 0xC);

void chuka_init(GameObject* obj, ChukaPlacement* params);
int chuka_SeqFn(void);
void chuka_release(void);
void chuka_initialise(void);

#endif /* MAIN_DLL_BADDIE_CHUKA_H_ */
