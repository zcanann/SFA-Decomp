#ifndef DLLS_OBJECTS_559_DFP_FLOORBA_H_
#define DLLS_OBJECTS_559_DFP_FLOORBA_H_

#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"

/* EN accesses establish this prefix through the halfword at 0x20.
 * The complete placement record size is not yet verified. */
typedef struct DfpFloorbarPlacementPrefix
{
    ObjPlacement base;
    s8 rotationHighByte;
    u8 rowIndex;
    u8 unk1A[2];
    s16 motionScaleDivisor;
    s16 placementGameBit1E;
    s16 initialLoweredGameBit;
} DfpFloorbarPlacementPrefix;

STATIC_ASSERT(offsetof(DfpFloorbarPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(DfpFloorbarPlacementPrefix, rotationHighByte) == 0x18);
STATIC_ASSERT(offsetof(DfpFloorbarPlacementPrefix, rowIndex) == 0x19);
STATIC_ASSERT(offsetof(DfpFloorbarPlacementPrefix, motionScaleDivisor) == 0x1C);
STATIC_ASSERT(offsetof(DfpFloorbarPlacementPrefix, placementGameBit1E) == 0x1E);
STATIC_ASSERT(offsetof(DfpFloorbarPlacementPrefix, initialLoweredGameBit) == 0x20);

/* DFP_Floorbar_getExtraSize returns the complete 0x0C-byte allocation. */
typedef struct DfpFloorbarState
{
    s16 placementGameBit1E; /* initialized only; no reader in this TU */
    s16 initialLoweredGameBit;
    u8 lowered;
    u8 rowIndex;
    u8 safeTileIndex;
    u8 previousShowSolutionState;
    GameObject* levelController;
} DfpFloorbarState;

STATIC_ASSERT(offsetof(DfpFloorbarState, placementGameBit1E) == 0x00);
STATIC_ASSERT(offsetof(DfpFloorbarState, initialLoweredGameBit) == 0x02);
STATIC_ASSERT(offsetof(DfpFloorbarState, lowered) == 0x04);
STATIC_ASSERT(offsetof(DfpFloorbarState, rowIndex) == 0x05);
STATIC_ASSERT(offsetof(DfpFloorbarState, safeTileIndex) == 0x06);
STATIC_ASSERT(offsetof(DfpFloorbarState, previousShowSolutionState) == 0x07);
STATIC_ASSERT(offsetof(DfpFloorbarState, levelController) == 0x08);
STATIC_ASSERT(sizeof(DfpFloorbarState) == 0x0C);

int dfpfloorbar_SeqFn(void);
int DFP_Floorbar_getExtraSize(void);
int DFP_Floorbar_getObjectTypeId(void);
void DFP_Floorbar_free(GameObject* obj);
void DFP_Floorbar_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 visible);
void DFP_Floorbar_hitDetect(GameObject* obj);
void DFP_Floorbar_update(GameObject* obj);
void DFP_Floorbar_init(GameObject* obj, DfpFloorbarPlacementPrefix* params);
void DFP_Floorbar_release(void);
void DFP_Floorbar_initialise(void);
extern u8 gDFPFloorbarSafeFloorTiles[9];
extern ObjectDescriptor10WithPadding gDfpfloorbarObjDescriptor;

#endif /* DLLS_OBJECTS_559_DFP_FLOORBA_H_ */
