#ifndef MAIN_DLL_DIM_DIMLOGFIRE_H_
#define MAIN_DLL_DIM_DIMLOGFIRE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/objanim_update.h"

/*
 * Per-object extra state for the dimlogfire burning log
 * (dimlogfire_getExtraSize == 0x24). init/update in DIMlavasmash.c,
 * free/SeqFn/render in DIMcannon.c.
 */
typedef struct DimLogFireState {
    int light; /* ModelLightStruct handle or 0 */
    int subObj; /* child object rendered/freed with the log */
    u8 pad08[8];
    f32 flickerTimerA; /* light flicker cadence pair */
    f32 flickerTimerB;
    u8 initMode; /* 0x18: from def initMode; ==0 starts lit (mode 1) else unlit (mode 2) */
    u8 pad19;
    u8 mode; /* 1 = lit (gamebit), 4 = from anim event 3 */
    u8 smokeToggle; /* anim event 1 toggles; partfx 215 while set */
    s8 strengthInit; /* def+0x1C */
    u8 dousedLatch;
    u8 strength; /* working copy of strengthInit */
    u8 pad1F;
    u8 unk20;
    u8 pad21[3];
} DimLogFireState;

STATIC_ASSERT(sizeof(DimLogFireState) == 0x24);

int MoonSeedPlantingSpot_SeqFn(int obj);
int CCGasVentControl_SeqFn(int obj);
int dimlogfire_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate);

#endif /* MAIN_DLL_DIM_DIMLOGFIRE_H_ */
