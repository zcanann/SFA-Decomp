#ifndef MAIN_DLL_DLL_00D1_TUMBLEWEEDBUSH_H_
#define MAIN_DLL_DLL_00D1_TUMBLEWEEDBUSH_H_

#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

struct GameObject;
struct BackpackState;

typedef struct TumbleweedBushState
{
    f32 scale;
    u8 pad04[4];
    u16 triggerRadius;
    u8 pad0A[2];
    struct GameObject* pieceObjects[4];
    f32 pieceOffsets[3][3];
    u8 pad40[0x4c - 0x40];
    u8 variant;
    u8 pad4D;
    u16 spawnedCount;
    u8 pieceCount;
    u8 pad51[3];
} TumbleweedBushState;

typedef struct TumbleweedBushPlacement
{
    ObjPlacement base;
    u8 rotZByte;
    u8 rotYByte;
    u8 rotXByte;
    u8 radiusByte;
    f32 scale;
    u8 pad20[3];
    u8 variant;
} TumbleweedBushPlacement;

STATIC_ASSERT(sizeof(TumbleweedBushState) == 0x54);
STATIC_ASSERT(offsetof(TumbleweedBushState, pieceObjects) == 0x0C);
STATIC_ASSERT(offsetof(TumbleweedBushState, pieceOffsets) == 0x1C);
STATIC_ASSERT(offsetof(TumbleweedBushState, variant) == 0x4C);
STATIC_ASSERT(offsetof(TumbleweedBushState, spawnedCount) == 0x4E);
STATIC_ASSERT(offsetof(TumbleweedBushState, pieceCount) == 0x50);
STATIC_ASSERT(sizeof(TumbleweedBushPlacement) == 0x24);
STATIC_ASSERT(offsetof(TumbleweedBushPlacement, radiusByte) == 0x1B);
STATIC_ASSERT(offsetof(TumbleweedBushPlacement, scale) == 0x1C);
STATIC_ASSERT(offsetof(TumbleweedBushPlacement, variant) == 0x23);

/* Bush variant anim.seqIds and the sibling tumbleweed seqId each one spawns.
 * The sibling ids match dll_00D2_tumbleweed.h's TUMBLEWEED_TYPE_1/3/4
 * (0x39d/0x4ba/0x4c1). */
#define TUMBLEWEEDBUSH_SEQ_A 0x28d /* -> sibling 0x39d (sun-gated) */
#define TUMBLEWEEDBUSH_SEQ_B 0x3fd /* -> sibling 0x3fb */
#define TUMBLEWEEDBUSH_SEQ_C 0x4b9 /* -> sibling 0x4ba */
#define TUMBLEWEEDBUSH_SEQ_D 0x4be /* -> sibling 0x4c1 */

#define TUMBLEWEEDBUSH_OBJGROUP 0x31 /* group scanned to find sibling bushes */

#define TUMBLEWEEDBUSH_SIBLING_A 0x39d
#define TUMBLEWEEDBUSH_SIBLING_B 0x3fb
#define TUMBLEWEEDBUSH_SIBLING_C 0x4ba
#define TUMBLEWEEDBUSH_SIBLING_D 0x4c1

extern ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor;


/* extern-cleanup: defining-file public prototypes */
s8 tumbleweedbush_spawnSibling(int* obj);
struct GameObject* tumbleweedbush_findNearestActive(f32* position);
void tumbleweedbush_activatePiece(struct GameObject* obj);
void tumbleweedbush_updateDetachedPiece(struct GameObject* piece, struct BackpackState* state);

#endif /* MAIN_DLL_DLL_00D1_TUMBLEWEEDBUSH_H_ */
