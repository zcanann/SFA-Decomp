#ifndef DLLS_OBJECTS_688_BROKENPIPE_H_
#define DLLS_OBJECTS_688_BROKENPIPE_H_

#include "game/objects/object_fwd.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"

/* Reader view only: the full EN placement extent is not established.
 * Do not use sizeof this prefix to allocate or copy placements. */
typedef struct BrokenPipePlacementPrefix
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale; /* Zero keeps the existing scale; otherwise normalized by 255. */
} BrokenPipePlacementPrefix;

/* brokenpipe_getExtraSize returns the required four-byte state size. */
typedef struct BrokenPipeState
{
    f32 hitEffectCooldown; /* Frame cooldown maintained by the priority-hit helper. */
} BrokenPipeState;

STATIC_ASSERT(offsetof(BrokenPipePlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(BrokenPipePlacementPrefix, rotZ) == 0x18);
STATIC_ASSERT(offsetof(BrokenPipePlacementPrefix, rotY) == 0x19);
STATIC_ASSERT(offsetof(BrokenPipePlacementPrefix, rotX) == 0x1A);
STATIC_ASSERT(offsetof(BrokenPipePlacementPrefix, scale) == 0x1b);
STATIC_ASSERT(offsetof(BrokenPipeState, hitEffectCooldown) == 0x00);
STATIC_ASSERT(sizeof(BrokenPipeState) == 4);

extern ObjectDescriptor gBrokenPipeObjDescriptor;

int brokenpipe_getExtraSize(void);
void brokenpipe_init(GameObject* obj, BrokenPipePlacementPrefix* setup);
void brokenpipe_update(GameObject* obj);

#endif /* DLLS_OBJECTS_688_BROKENPIPE_H_ */
