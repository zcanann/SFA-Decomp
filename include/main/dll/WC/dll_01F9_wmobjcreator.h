#ifndef MAIN_DLL_WC_WCPRESSURESWITCH_H_
#define MAIN_DLL_WC_WCPRESSURESWITCH_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct WmObjCreatorState
{
    s16 gameBit;     /* 0x00: spawn gate, -1 = always */
    s16 spawnPeriod; /* 0x02 */
    s16 spawnTimer;  /* 0x04 */
    s16 spawnJitter; /* 0x06: randomGetRange(0, jitter) added per cycle */
} WmObjCreatorState;

typedef struct WmObjCreatorPlacement
{
    ObjPlacement base;
    s16 gameBit;
    s16 spawnMode;
    s16 spawnPeriod;
    s8 yaw;
    s8 spawnJitter;
    u8 pad20[4];
} WmObjCreatorPlacement;

typedef struct WmGalleonState
{
    u8 pad00[0xC];
    u8 active; /* 0x0c: cleared on a non-map-change free */
    u8 pad0D[3];
} WmGalleonState;

void WM_ObjCreator_update(struct GameObject* obj);
int WM_Galleon_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
void WM_Galleon_free(int* obj, int leavingMap);
void WM_Galleon_render(void* obj, int p2, int p3, int p4, int p5, s8 visible);

#endif /* MAIN_DLL_WC_WCPRESSURESWITCH_H_ */
