#ifndef DLLS_OBJECTS_567_DFPSPPL_H_
#define DLLS_OBJECTS_567_DFPSPPL_H_

#include "types.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"

/* Retail DFPSpPl_getExtraSize allocates six bytes. */
typedef struct DfpSpellPlaceState {
    s16 completionGameBit;
    s16 activationGameBit;
    u8 completionLatched;
    u8 unknown05;
} DfpSpellPlaceState;

STATIC_ASSERT(offsetof(DfpSpellPlaceState, completionGameBit) == 0x00);
STATIC_ASSERT(offsetof(DfpSpellPlaceState, activationGameBit) == 0x02);
STATIC_ASSERT(offsetof(DfpSpellPlaceState, completionLatched) == 0x04);
STATIC_ASSERT(offsetof(DfpSpellPlaceState, unknown05) == 0x05);
STATIC_ASSERT(sizeof(DfpSpellPlaceState) == 0x06);

/* EN reader view only: the complete placement allocation is not established.
 * EN rev1 and JP serialized records are 0x24 bytes. Do not allocate or copy a
 * placement using sizeof this prefix.
 */
typedef struct DfpSpellPlacePlacementPrefix {
    ObjPlacement base;
    s8 rotationXByte;
    u8 unknown19[5];
    s16 completionGameBit;
    s16 activationGameBit;
} DfpSpellPlacePlacementPrefix;

STATIC_ASSERT(offsetof(DfpSpellPlacePlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(DfpSpellPlacePlacementPrefix, rotationXByte) == 0x18);
STATIC_ASSERT(offsetof(DfpSpellPlacePlacementPrefix, unknown19) == 0x19);
STATIC_ASSERT(offsetof(DfpSpellPlacePlacementPrefix, completionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DfpSpellPlacePlacementPrefix, activationGameBit) == 0x20);

extern ObjectDescriptor gDFPSpPlObjDescriptor;

int DFPSpPl_getExtraSize(void);
int DFPSpPl_getObjectTypeId(void);
void DFPSpPl_free(void);
void DFPSpPl_render(void);
void DFPSpPl_hitDetect(void);
void DFPSpPl_update(GameObject* obj);
void DFPSpPl_init(GameObject* obj, DfpSpellPlacePlacementPrefix* mapData);
void DFPSpPl_release(void);
void DFPSpPl_initialise(void);

#endif /* DLLS_OBJECTS_567_DFPSPPL_H_ */
