#ifndef DLLS_OBJECTS_243_FLAMEBLAST_H_
#define DLLS_OBJECTS_243_FLAMEBLAST_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef struct FlameblastPlacement {
    ObjPlacement base; /* 0x00 */
    u8 pad18[2];       /* 0x18 */
    s16 streamIndex;   /* 0x1A: initial launch-cycle phase */
    u8 pad1C[8];       /* 0x1C */
} FlameblastPlacement;

typedef struct FlameblastState {
    f32 cycleTimer;          /* 0x00 */
    f32 launchOriginX;       /* 0x04 */
    f32 launchOriginY;       /* 0x08 */
    f32 launchOriginZ;       /* 0x0C */
    u8 freeRequested;        /* 0x10 */
    u8 hitVolumeDelayCycles; /* 0x11 */
    u8 pad12[2];             /* 0x12 */
} FlameblastState;

STATIC_ASSERT(offsetof(FlameblastPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(FlameblastPlacement, pad18) == 0x18);
STATIC_ASSERT(offsetof(FlameblastPlacement, streamIndex) == 0x1A);
STATIC_ASSERT(offsetof(FlameblastPlacement, pad1C) == 0x1C);
STATIC_ASSERT(sizeof(FlameblastPlacement) == 0x24);

STATIC_ASSERT(offsetof(FlameblastState, cycleTimer) == 0x0);
STATIC_ASSERT(offsetof(FlameblastState, launchOriginX) == 0x4);
STATIC_ASSERT(offsetof(FlameblastState, launchOriginY) == 0x8);
STATIC_ASSERT(offsetof(FlameblastState, launchOriginZ) == 0xC);
STATIC_ASSERT(offsetof(FlameblastState, freeRequested) == 0x10);
STATIC_ASSERT(offsetof(FlameblastState, hitVolumeDelayCycles) == 0x11);
STATIC_ASSERT(offsetof(FlameblastState, pad12) == 0x12);
STATIC_ASSERT(sizeof(FlameblastState) == 0x14);

void flameblast_requestFree(GameObject* obj);
int flameblast_seedVelocity(GameObject* obj, FlameblastState* state);
int flameblast_getExtraSize(void);
void flameblast_render(GameObject* obj);
void flameblast_update(GameObject* obj);
void flameblast_init(GameObject* obj, FlameblastPlacement* placement);

extern ObjectDescriptor gFlameblastObjDescriptor;

#endif /* DLLS_OBJECTS_243_FLAMEBLAST_H_ */
