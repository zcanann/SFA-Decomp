#ifndef DLLS_OBJECTS_552_H_
#define DLLS_OBJECTS_552_H_

#include "types.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"

/* Retail VFP_SpellPlace_getExtraSize allocates six bytes. */
typedef struct VfpSpellPlaceState {
    s16 completionGameBit;
    s16 activationGameBit;
    u8 completionLatched;
    u8 unknown05;
} VfpSpellPlaceState;

STATIC_ASSERT(offsetof(VfpSpellPlaceState, completionGameBit) == 0x00);
STATIC_ASSERT(offsetof(VfpSpellPlaceState, activationGameBit) == 0x02);
STATIC_ASSERT(offsetof(VfpSpellPlaceState, completionLatched) == 0x04);
STATIC_ASSERT(offsetof(VfpSpellPlaceState, unknown05) == 0x05);
STATIC_ASSERT(sizeof(VfpSpellPlaceState) == 0x06);

/* EN reader view only: the complete placement allocation is not established.
 * EN rev1 and JP serialized records are 0x24 bytes. Do not allocate or copy a
 * placement using sizeof this prefix.
 */
typedef struct VfpSpellPlacePlacementPrefix {
    ObjPlacement base;
    s8 rotationXByte;
    u8 unknown19[5];
    s16 completionGameBit;
    s16 activationGameBit;
} VfpSpellPlacePlacementPrefix;

STATIC_ASSERT(offsetof(VfpSpellPlacePlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(VfpSpellPlacePlacementPrefix, rotationXByte) == 0x18);
STATIC_ASSERT(offsetof(VfpSpellPlacePlacementPrefix, unknown19) == 0x19);
STATIC_ASSERT(offsetof(VfpSpellPlacePlacementPrefix, completionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(VfpSpellPlacePlacementPrefix, activationGameBit) == 0x20);

extern ObjectDescriptor gVFP_SpellPlaceObjDescriptor;

int VFP_SpellPlace_getExtraSize(void);
int VFP_SpellPlace_getObjectTypeId(void);
void VFP_SpellPlace_free(void);
void VFP_SpellPlace_render(void);
void VFP_SpellPlace_hitDetect(void);
void VFP_SpellPlace_update(GameObject* spellPlace);
void VFP_SpellPlace_init(GameObject* spellPlace, VfpSpellPlacePlacementPrefix* mapData);
void VFP_SpellPlace_release(void);
void VFP_SpellPlace_initialise(void);

#endif /* DLLS_OBJECTS_552_H_ */
