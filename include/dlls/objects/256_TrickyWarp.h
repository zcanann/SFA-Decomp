#ifndef DLLS_OBJECTS_256_TRICKYWARP_H_
#define DLLS_OBJECTS_256_TRICKYWARP_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

#define TRICKYWARP_PLACEMENT_SIZE      0x20
#define TRICKYWARP_STATE_SIZE          0x64
#define TRICKYWARP_CURVE_NODE_CAPACITY 0x18

/* Retail romlists use the complete fixed-size 0x20-byte setup record. */
typedef struct TrickyWarpPlacement {
    ObjPlacement base; /* 0x00 */
    u8 unknown18[2];   /* 0x18 */
    u8 rotXByte;       /* 0x1A */
    u8 pad1B[5];       /* 0x1B */
} TrickyWarpPlacement;

/* TrickyWarp_getExtraSize allocates the complete 0x64-byte state block. */
typedef struct TrickyWarpState {
    u8 warpPointWalkGroup;                                  /* 0x00 */
    u8 registeredAsWarpCandidate;                           /* 0x01 */
    u8 pad02[2];                                            /* 0x02 */
    s32 linkedWarpCurveIds[TRICKYWARP_CURVE_NODE_CAPACITY]; /* 0x04 */
} TrickyWarpState;

STATIC_ASSERT(offsetof(TrickyWarpPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(TrickyWarpPlacement, unknown18) == 0x18);
STATIC_ASSERT(offsetof(TrickyWarpPlacement, rotXByte) == 0x1A);
STATIC_ASSERT(offsetof(TrickyWarpPlacement, pad1B) == 0x1B);
STATIC_ASSERT(sizeof(TrickyWarpPlacement) == TRICKYWARP_PLACEMENT_SIZE);

STATIC_ASSERT(offsetof(TrickyWarpState, warpPointWalkGroup) == 0x0);
STATIC_ASSERT(offsetof(TrickyWarpState, registeredAsWarpCandidate) == 0x1);
STATIC_ASSERT(offsetof(TrickyWarpState, pad02) == 0x2);
STATIC_ASSERT(offsetof(TrickyWarpState, linkedWarpCurveIds) == 0x4);
STATIC_ASSERT(sizeof(TrickyWarpState) == TRICKYWARP_STATE_SIZE);

void TrickyWarp_free(GameObject* obj);
int TrickyWarp_getExtraSize(void);
void TrickyWarp_update(GameObject* obj);
int TrickyWarp_isPlayerReachable(GameObject* obj, TrickyWarpState* state);
void TrickyWarp_init(GameObject* obj, TrickyWarpPlacement* placement);

extern ObjectDescriptor gTrickyWarpObjDescriptor;

#endif /* DLLS_OBJECTS_256_TRICKYWARP_H_ */
