#ifndef DLLS_OBJECTS_563_DFP_STATUE1_H_
#define DLLS_OBJECTS_563_DFP_STATUE1_H_

#include "types.h"
#include "main/objseq.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object.h"

/* Retail DFP_Statue1_getExtraSize allocates 0xA bytes. */
typedef struct DfpStatue1State {
    s16 unknown00;
    s16 activationGameBit;
    s16 effectTimer;
    u8 sequenceActive;
    u8 unknown07;
    u8 deactivationPending;
    u8 unknown09;
} DfpStatue1State;

STATIC_ASSERT(offsetof(DfpStatue1State, unknown00) == 0x00);
STATIC_ASSERT(offsetof(DfpStatue1State, activationGameBit) == 0x02);
STATIC_ASSERT(offsetof(DfpStatue1State, effectTimer) == 0x04);
STATIC_ASSERT(offsetof(DfpStatue1State, sequenceActive) == 0x06);
STATIC_ASSERT(offsetof(DfpStatue1State, unknown07) == 0x07);
STATIC_ASSERT(offsetof(DfpStatue1State, deactivationPending) == 0x08);
STATIC_ASSERT(offsetof(DfpStatue1State, unknown09) == 0x09);
STATIC_ASSERT(sizeof(DfpStatue1State) == 0x0A);

/* EN reader view: the full serialized allocation is not yet established.
 * EN rev1 and JP placements are 0x24 bytes. Do not allocate or copy a placement
 * using sizeof this prefix.
 */
typedef struct DfpStatue1PlacementPrefix {
    ObjPlacement base;
    s8 rotationXByte;
    u8 unknown19;
    u8 unknown1A[4];
    s16 unknown1E;
    s16 activationGameBit;
} DfpStatue1PlacementPrefix;

STATIC_ASSERT(offsetof(DfpStatue1PlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(DfpStatue1PlacementPrefix, rotationXByte) == 0x18);
STATIC_ASSERT(offsetof(DfpStatue1PlacementPrefix, unknown19) == 0x19);
STATIC_ASSERT(offsetof(DfpStatue1PlacementPrefix, unknown1A) == 0x1A);
STATIC_ASSERT(offsetof(DfpStatue1PlacementPrefix, unknown1E) == 0x1E);
STATIC_ASSERT(offsetof(DfpStatue1PlacementPrefix, activationGameBit) == 0x20);

u32 dfpstatue1_SeqFn(GameObject* obj, u32 unused, ObjSeqState* animUpdate);
void dfpstatue1_updateState(GameObject* obj);

extern ObjectDescriptor gDfpstatue1ObjDescriptor;

int DFP_Statue1_getExtraSize(void);
int DFP_Statue1_getObjectTypeId(void);
void DFP_Statue1_free(void);
void DFP_Statue1_render(void);
void DFP_Statue1_hitDetect(void);
void DFP_Statue1_update(GameObject* obj);
void DFP_Statue1_init(GameObject* obj, DfpStatue1PlacementPrefix* mapData);
void DFP_Statue1_release(void);
void DFP_Statue1_initialise(void);

#endif /* DLLS_OBJECTS_563_DFP_STATUE1_H_ */
