#ifndef DLLS_OBJECTS_686_WATERFLOWWE_H_
#define DLLS_OBJECTS_686_WATERFLOWWE_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

/* waterflowwe_getExtraSize allocates the complete eight-byte filtered-current state. */
typedef struct WaterFlowWeState {
    f32 currentX;
    f32 currentZ;
} WaterFlowWeState;

/* Accessed reader view only. The complete EN serialized extent is not established;
 * do not use sizeof this prefix to allocate or copy placements. */
typedef struct WaterFlowWePlacementPrefix {
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale; /* Nonzero values scale the model base by scale / 255. */
    u8 pad1C[3];
    u8 phaseDriverDisabled; /* Nonzero prevents this object from becoming the shared phase driver. */
} WaterFlowWePlacementPrefix;

STATIC_ASSERT(offsetof(WaterFlowWeState, currentX) == 0x0);
STATIC_ASSERT(offsetof(WaterFlowWeState, currentZ) == 0x4);
STATIC_ASSERT(sizeof(WaterFlowWeState) == 0x8);
STATIC_ASSERT(offsetof(WaterFlowWePlacementPrefix, base) == 0x0);
STATIC_ASSERT(offsetof(WaterFlowWePlacementPrefix, rotZ) == 0x18);
STATIC_ASSERT(offsetof(WaterFlowWePlacementPrefix, rotY) == 0x19);
STATIC_ASSERT(offsetof(WaterFlowWePlacementPrefix, rotX) == 0x1A);
STATIC_ASSERT(offsetof(WaterFlowWePlacementPrefix, scale) == 0x1b);
STATIC_ASSERT(offsetof(WaterFlowWePlacementPrefix, phaseDriverDisabled) == 0x1f);

extern GameObject* gWaterFlowPhaseDriver;
extern f32 gWaterFlowIdlePhase; /* Used by both idle and current-driven animation moves. */
extern f32 gWaterFlowFlowPhase; /* Advanced and reset, but not read by either animation branch. */

void waterflowwe_calcCurrentVector(GameObject* obj, f32* currentX, f32* currentZ);
int waterflowwe_getExtraSize(void);
int waterflowwe_getObjectTypeId(void);
void waterflowwe_init(GameObject* obj, WaterFlowWePlacementPrefix* setup);
void waterflowwe_free(GameObject* obj);
void waterflowwe_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void waterflowwe_hitDetect(void);
void waterflowwe_update(GameObject* obj);
void waterflowwe_release(void);
void waterflowwe_initialise(void);

extern ObjectDescriptor gWaterFlowWeObjDescriptor;

#endif /* DLLS_OBJECTS_686_WATERFLOWWE_H_ */
