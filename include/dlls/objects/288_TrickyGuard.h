#ifndef DLLS_OBJECTS_288_TRICKYGUARD_H_
#define DLLS_OBJECTS_288_TRICKYGUARD_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

#define TRICKY_GUARD_SPOT_STATE_SIZE 0x8

/* Only the accessed placement prefix is recovered; the complete retail width is not established. */
typedef struct TrickyGuardSpotPlacement {
    ObjPlacement base;        /* 0x00 */
    s8 rotationX;             /* 0x18 */
    u8 guardDurationSeconds;  /* 0x19 */
    s16 triggerRadius;        /* 0x1A */
    u8 pad1C[2];              /* 0x1C */
    s16 trickyInRangeGameBit; /* 0x1E */
} TrickyGuardSpotPlacement;

typedef struct TrickyGuardSpotStateFlags {
    u8 trickyInRange : 1;
    u8 : 7;
} TrickyGuardSpotStateFlags;

typedef struct TrickyGuardSpotState {
    u32 guardTimer;                  /* 0x00 */
    TrickyGuardSpotStateFlags flags; /* 0x04 */
    u8 pad05[3];                     /* 0x05 */
} TrickyGuardSpotState;

STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, rotationX) == 0x18);
STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, guardDurationSeconds) == 0x19);
STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, triggerRadius) == 0x1A);
STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, pad1C) == 0x1C);
STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, trickyInRangeGameBit) == 0x1E);

STATIC_ASSERT(sizeof(TrickyGuardSpotStateFlags) == 0x1);
STATIC_ASSERT(offsetof(TrickyGuardSpotState, guardTimer) == 0x0);
STATIC_ASSERT(offsetof(TrickyGuardSpotState, flags) == 0x4);
STATIC_ASSERT(offsetof(TrickyGuardSpotState, pad05) == 0x5);
STATIC_ASSERT(sizeof(TrickyGuardSpotState) == TRICKY_GUARD_SPOT_STATE_SIZE);

int TrickyGuardSpot_getExtraSize(void);
void TrickyGuardSpot_free(GameObject* obj);
void TrickyGuardSpot_render(void);
void TrickyGuardSpot_update(GameObject* obj);
void TrickyGuardSpot_init(GameObject* obj, TrickyGuardSpotPlacement* placement);

extern ObjectDescriptor gTrickyGuardSpotObjDescriptor;

#endif /* DLLS_OBJECTS_288_TRICKYGUARD_H_ */
