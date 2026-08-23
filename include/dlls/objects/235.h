#ifndef DLLS_OBJECTS_235_H_
#define DLLS_OBJECTS_235_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef struct SideRepelPlacement {
    ObjPlacement base; /* 0x00 */
    u16 minDistance;  /* 0x18: avoidance distance before Tricky's 0.1 scale */
    u16 moveDistance; /* 0x1A: push distance before Tricky's 0.1 scale */
} SideRepelPlacement;

typedef struct SideRepelState {
    u8 unused; /* 0x00 */
} SideRepelState;

STATIC_ASSERT(offsetof(SideRepelPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(SideRepelPlacement, minDistance) == 0x18);
STATIC_ASSERT(offsetof(SideRepelPlacement, moveDistance) == 0x1A);
STATIC_ASSERT(sizeof(SideRepelPlacement) == 0x1C);

STATIC_ASSERT(offsetof(SideRepelState, unused) == 0x0);
STATIC_ASSERT(sizeof(SideRepelState) == 0x1);

int siderepel_getExtraSize(void);
void siderepel_free(GameObject* obj);
void siderepel_init(GameObject* obj, SideRepelPlacement* placement);

extern ObjectDescriptor gSiderepelObjDescriptor;

#endif /* DLLS_OBJECTS_235_H_ */
