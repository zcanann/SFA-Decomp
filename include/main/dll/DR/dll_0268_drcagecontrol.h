#ifndef MAIN_DLL_DR_DLL_0268_DRCAGECONTROL_H_
#define MAIN_DLL_DR_DLL_0268_DRCAGECONTROL_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct DRCageControlFlags
{
    u8 watchBitSet : 1;
    u8 sequenceStarted : 1;
    u8 initiallyArmed : 1;
    u8 unused : 5;
} DRCageControlFlags;

typedef struct DRCageControlState
{
    s32 sequenceId;
    DRCageControlFlags flags;
} DRCageControlState;

typedef struct CageControlPlacement
{
    ObjPlacement base;
    u8 pad18[6];
    s16 armGameBit;   /* 0x1E: game bit that pre-opens the cage */
    s16 watchGameBit; /* 0x20: drives the pickup sfx + completion */
    u8 pad22[0x28 - 0x22];
} CageControlPlacement;

STATIC_ASSERT(sizeof(DRCageControlFlags) == 0x1);
STATIC_ASSERT(offsetof(DRCageControlState, sequenceId) == 0x0);
STATIC_ASSERT(offsetof(DRCageControlState, flags) == 0x4);
STATIC_ASSERT(offsetof(CageControlPlacement, armGameBit) == 0x1e);
STATIC_ASSERT(offsetof(CageControlPlacement, watchGameBit) == 0x20);
STATIC_ASSERT(sizeof(CageControlPlacement) == 0x28);


int DR_CageControl_SeqFn(GameObject* obj);
int DR_CageControl_getExtraSize(void);
int DR_CageControl_getObjectTypeId(void);
void DR_CageControl_free(void);
void DR_CageControl_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, s8 visible);
void DR_CageControl_hitDetect(void);
void DR_CageControl_update(GameObject* obj);
void DR_CageControl_init(GameObject* obj, CageControlPlacement* placement);
void DR_CageControl_release(void);
void DR_CageControl_initialise(void);

extern ObjectDescriptor gDrCageControlObjDescriptor;

#endif /* MAIN_DLL_DR_DLL_0268_DRCAGECONTROL_H_ */
