#ifndef DLLS_OBJECTS_572_DFP_POWERSL_H_
#define DLLS_OBJECTS_572_DFP_POWERSL_H_

#include "global.h"
#include "types.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"



/* Retail getExtraSize allocates exactly 0x0C bytes. */
typedef struct DfpPowerSlState {
  s32 sequenceStartFrame;
  s32 effectId;
  s32 disableEffectGameBit;
} DfpPowerSlState;

/* Mutable EN reader view: init replaces nonpositive frame/effect parameters
 * with one. The full placement allocation is unproven; do not allocate or copy
 * a placement using sizeof this prefix.
 */
typedef struct DfpPowerSlPlacementPrefix {
  ObjPlacement base;
  s8 rotationXByte;
  u8 unknown19;
  s16 sequenceStartFrame;
  s16 effectId;
  u8 unknown1E[2];
  s16 disableEffectGameBit;
} DfpPowerSlPlacementPrefix;

STATIC_ASSERT(sizeof(DfpPowerSlState) == 0x0C);
STATIC_ASSERT(offsetof(DfpPowerSlState, sequenceStartFrame) == 0x00);
STATIC_ASSERT(offsetof(DfpPowerSlState, effectId) == 0x04);
STATIC_ASSERT(offsetof(DfpPowerSlState, disableEffectGameBit) == 0x08);

STATIC_ASSERT(offsetof(DfpPowerSlPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(DfpPowerSlPlacementPrefix, rotationXByte) == 0x18);
STATIC_ASSERT(offsetof(DfpPowerSlPlacementPrefix, unknown19) == 0x19);
STATIC_ASSERT(offsetof(DfpPowerSlPlacementPrefix, sequenceStartFrame) == 0x1A);
STATIC_ASSERT(offsetof(DfpPowerSlPlacementPrefix, effectId) == 0x1C);
STATIC_ASSERT(offsetof(DfpPowerSlPlacementPrefix, unknown1E) == 0x1E);
STATIC_ASSERT(offsetof(DfpPowerSlPlacementPrefix, disableEffectGameBit) == 0x20);

extern ObjectDescriptor gDfppowerslObjDescriptor;

int dfppowersl_getExtraSize(void);
int dfppowersl_spawnHitEffects(GameObject *obj);
void dfppowersl_free(GameObject *obj);
void dfppowersl_render(GameObject *obj);
void dfppowersl_update(GameObject *obj);
void dfppowersl_init(GameObject *obj,DfpPowerSlPlacementPrefix *mapData);

#endif /* DLLS_OBJECTS_572_DFP_POWERSL_H_ */
