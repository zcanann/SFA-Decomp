#ifndef MAIN_DLL_DLL_0100_TRICKYWARP_H_
#define MAIN_DLL_DLL_0100_TRICKYWARP_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

#define TRICKYWARP_CURVE_NODE_CAPACITY 0x18

/* Retail romlists use a fixed eight-byte parameter tail (0x20 total). */
typedef struct TrickyWarpPlacement
{
    ObjPlacement base;
    u8 unk18;
    u8 unk19;
    u8 rotXByte;
    u8 pad1B[0x20 - 0x1B];
} TrickyWarpPlacement;

typedef struct TrickyWarpState
{
    u8 patchGroup;
    u8 active;
    u8 pad02[2];
    int curveNodeIds[TRICKYWARP_CURVE_NODE_CAPACITY];
} TrickyWarpState;

STATIC_ASSERT(sizeof(TrickyWarpPlacement) == 0x20);
STATIC_ASSERT(offsetof(TrickyWarpPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(TrickyWarpPlacement, rotXByte) == 0x1A);
STATIC_ASSERT(sizeof(TrickyWarpState) == 0x64);
STATIC_ASSERT(offsetof(TrickyWarpState, patchGroup) == 0x0);
STATIC_ASSERT(offsetof(TrickyWarpState, active) == 0x1);
STATIC_ASSERT(offsetof(TrickyWarpState, curveNodeIds) == 0x4);

int TrickyWarp_getExtraSize(void);
void TrickyWarp_free(GameObject* obj);
void TrickyWarp_update(GameObject* obj);
int TrickyWarp_isPlayerReachable(GameObject* obj, TrickyWarpState* state);
void TrickyWarp_init(GameObject* obj, TrickyWarpPlacement* placement);

extern ObjectDescriptor gTrickyWarpObjDescriptor;

#endif /* MAIN_DLL_DLL_0100_TRICKYWARP_H_ */
