#ifndef DLLS_OBJECTS_571_DFP_LIGHTNI_H_
#define DLLS_OBJECTS_571_DFP_LIGHTNI_H_

#include "global.h"
#include "types.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"
#include "main/lightningeffect.h"

/* Mutable EN placement reader: init repairs nonpositive density parameters.
 * The full EN allocation is unproven; EN rev1 and JP records are 0x24 bytes.
 * Do not allocate or copy a placement using sizeof this prefix.
 */
typedef struct DfpLightniPlacementPrefix {
    ObjPlacement base;
    s8 widthSteps;
    s8 lifetimeTensOfFrames;
    s16 boltSegmentDensityParam;
    s16 strandSegmentDensityParam;
    u8 unknown1E[2];
    s16 targetPlayerGameBit;
} DfpLightniPlacementPrefix;

/* Retail getExtraSize returns 0x1C; all fields below are accessed by this TU. */
typedef struct DfpLightniState {
    LightningEffect* effectHandle;
    f32 timer;
    f32 triggerTime;
    f32 boltSegmentDensity;
    f32 strandSegmentDensity;
    s16 widthSteps;
    s16 effectLifetimeFrames;
    s32 targetPlayerGameBit;
} DfpLightniState;

STATIC_ASSERT(offsetof(DfpLightniPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(DfpLightniPlacementPrefix, widthSteps) == 0x18);
STATIC_ASSERT(offsetof(DfpLightniPlacementPrefix, lifetimeTensOfFrames) == 0x19);
STATIC_ASSERT(offsetof(DfpLightniPlacementPrefix, boltSegmentDensityParam) == 0x1A);
STATIC_ASSERT(offsetof(DfpLightniPlacementPrefix, strandSegmentDensityParam) == 0x1C);
STATIC_ASSERT(offsetof(DfpLightniPlacementPrefix, unknown1E) == 0x1E);
STATIC_ASSERT(offsetof(DfpLightniPlacementPrefix, targetPlayerGameBit) == 0x20);

STATIC_ASSERT(sizeof(DfpLightniState) == 0x1C);
STATIC_ASSERT(offsetof(DfpLightniState, effectHandle) == 0x00);
STATIC_ASSERT(offsetof(DfpLightniState, timer) == 0x04);
STATIC_ASSERT(offsetof(DfpLightniState, triggerTime) == 0x08);
STATIC_ASSERT(offsetof(DfpLightniState, boltSegmentDensity) == 0x0C);
STATIC_ASSERT(offsetof(DfpLightniState, strandSegmentDensity) == 0x10);
STATIC_ASSERT(offsetof(DfpLightniState, widthSteps) == 0x14);
STATIC_ASSERT(offsetof(DfpLightniState, effectLifetimeFrames) == 0x16);
STATIC_ASSERT(offsetof(DfpLightniState, targetPlayerGameBit) == 0x18);

extern ObjectDescriptor gDfplightniObjDescriptor;

int DFP_Lightni_getExtraSize(void);
void DFP_Lightni_free(GameObject* obj);
void DFP_Lightni_render(GameObject* obj);
void DFP_Lightni_update(GameObject* obj);
void DFP_Lightni_init(GameObject* obj, DfpLightniPlacementPrefix* mapData);
#endif /* DLLS_OBJECTS_571_DFP_LIGHTNI_H_ */
