#ifndef MAIN_DLL_DIM_DIMLOGFIRE_H_
#define MAIN_DLL_DIM_DIMLOGFIRE_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "global.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct DimlogfirePlacement
{
    ObjPlacement base;
    u8 pad18[6];
    s16 douseGameBit;
} DimlogfirePlacement;

typedef struct DimlogfireObjectDef
{
    ObjPlacement base;
    u8 pad18[2];
    s16 initMode;
    s16 strengthInit;
    s16 douseGameBit;
} DimlogfireObjectDef;

/*
 * Per-object extra state for the dimlogfire burning log
 * (DIMLogFire_getExtraSize == 0x24). init/update in DIMlavasmash.c,
 * free/SeqFn/render in DIMcannon.c.
 */
typedef struct DimLogFireState
{
    int light;  /* ModelLightStruct handle or 0 */
    int subObj; /* child object rendered/freed with the log */
    u8 pad08[8];
    f32 flickerTimerA; /* light flicker cadence pair */
    f32 flickerTimerB;
    u8 initMode; /* 0x18: from def initMode; ==0 starts lit (mode 1) else unlit (mode 2) */
    u8 pad19;
    u8 mode;         /* 1 = lit (gamebit), 4 = from anim event 3 */
    u8 smokeToggle;  /* anim event 1 toggles; partfx 215 while set */
    s8 strengthInit; /* def+0x1C */
    u8 dousedLatch;
    u8 strength; /* working copy of strengthInit */
    u8 pad1F;
    u8 unk20;
    u8 pad21[3];
} DimLogFireState;

STATIC_ASSERT(sizeof(DimLogFireState) == 0x24);

int MoonSeedPlantingSpot_SeqFn(int obj);
int CCGasVentControl_SeqFn(GameObject* obj);
int DIMLogFire_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int DIMLogFire_getExtraSize(void);
int DIMLogFire_getObjectTypeId(void);
void DIMLogFire_free(GameObject* obj, int mode);
void DIMLogFire_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DIMLogFire_update(GameObject* obj);
void DIMLogFire_init(int obj, DimlogfireObjectDef* def);

STATIC_ASSERT(offsetof(DimlogfirePlacement, douseGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DimlogfireObjectDef, initMode) == 0x1A);
STATIC_ASSERT(offsetof(DimlogfireObjectDef, douseGameBit) == 0x1E);

#endif /* MAIN_DLL_DIM_DIMLOGFIRE_H_ */
