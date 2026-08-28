#ifndef DLLS_OBJECTS_209_TUMBLEWEEDB_H_
#define DLLS_OBJECTS_209_TUMBLEWEEDB_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

struct TumbleweedState;

#define TUMBLEWEED_BUSH_PIECE_CAPACITY 3
#define TUMBLEWEED_BUSH_SIBLING_B      0x3FB

typedef struct TumbleweedBushState {
    f32 scale;                                                /* 0x00 */
    u8 pad04[4];                                              /* 0x04 */
    u16 triggerRadius;                                        /* 0x08 */
    u8 pad0A[2];                                              /* 0x0A */
    GameObject* pieceObjects[TUMBLEWEED_BUSH_PIECE_CAPACITY]; /* 0x0C */
    u8 pad18[4];                                              /* 0x18 */
    f32 pieceOffsets[TUMBLEWEED_BUSH_PIECE_CAPACITY][3];      /* 0x1C */
    u8 pad40[0x4C - 0x40];                                    /* 0x40 */
    u8 variant;                                               /* 0x4C */
    u8 pad4D;                                                 /* 0x4D */
    u16 spawnedCount;                                         /* 0x4E */
    u8 pieceCount;                                            /* 0x50 */
    u8 pad51[0x54 - 0x51];                                    /* 0x51 */
} TumbleweedBushState;

typedef struct TumbleweedBushPlacement {
    ObjPlacement base; /* 0x00 */
    u8 rotZByte;       /* 0x18 */
    u8 rotYByte;       /* 0x19 */
    u8 rotXByte;       /* 0x1A */
    u8 radiusByte;     /* 0x1B */
    f32 scale;         /* 0x1C */
    u8 pad20[3];       /* 0x20 */
    u8 variant;        /* 0x23 */
} TumbleweedBushPlacement;

typedef struct TumbleweedBushInterface {
    ObjectInterface base;
    void (*removePieceReference)(GameObject* bush, GameObject* piece);
} TumbleweedBushInterface;

#define TUMBLEWEED_BUSH_INTERFACE(bush) ((TumbleweedBushInterface*)*((GameObject*)(bush))->anim.dll)

STATIC_ASSERT(offsetof(TumbleweedBushState, scale) == 0x0);
STATIC_ASSERT(offsetof(TumbleweedBushState, triggerRadius) == 0x8);
STATIC_ASSERT(offsetof(TumbleweedBushState, pieceObjects) == 0xC);
STATIC_ASSERT(offsetof(TumbleweedBushState, pad18) == 0x18);
STATIC_ASSERT(offsetof(TumbleweedBushState, pieceOffsets) == 0x1C);
STATIC_ASSERT(offsetof(TumbleweedBushState, variant) == 0x4C);
STATIC_ASSERT(offsetof(TumbleweedBushState, spawnedCount) == 0x4E);
STATIC_ASSERT(offsetof(TumbleweedBushState, pieceCount) == 0x50);
STATIC_ASSERT(sizeof(TumbleweedBushState) == 0x54);

STATIC_ASSERT(offsetof(TumbleweedBushPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(TumbleweedBushPlacement, rotZByte) == 0x18);
STATIC_ASSERT(offsetof(TumbleweedBushPlacement, rotYByte) == 0x19);
STATIC_ASSERT(offsetof(TumbleweedBushPlacement, rotXByte) == 0x1A);
STATIC_ASSERT(offsetof(TumbleweedBushPlacement, radiusByte) == 0x1B);
STATIC_ASSERT(offsetof(TumbleweedBushPlacement, scale) == 0x1C);
STATIC_ASSERT(offsetof(TumbleweedBushPlacement, variant) == 0x23);
STATIC_ASSERT(sizeof(TumbleweedBushPlacement) == 0x24);

STATIC_ASSERT(offsetof(TumbleweedBushInterface, removePieceReference) == 0x20);
STATIC_ASSERT(sizeof(TumbleweedBushInterface) == 0x24);

s8 tumbleweedbush_spawnSibling(GameObject* obj);
void tumbleweedbush_removePieceReference(GameObject* obj, GameObject* piece);
GameObject* tumbleweedbush_findNearestActive(f32* position);
void tumbleweedbush_activatePiece(GameObject* obj);
void tumbleweedbush_updateDetachedPiece(GameObject* piece, struct TumbleweedState* state);

int TumbleWeedBush_getExtraSize(void);
int TumbleWeedBush_getObjectTypeId(void);
void TumbleWeedBush_free(GameObject* obj);
void TumbleWeedBush_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible);
void TumbleWeedBush_hitDetect(GameObject* obj);
void TumbleWeedBush_update(GameObject* obj);
void TumbleWeedBush_init(GameObject* obj, TumbleweedBushPlacement* placement, int flags);
void TumbleWeedBush_release(void);
void TumbleWeedBush_initialise(void);

extern f32 gTumbleweedBushPieceOffsetTable[2][4][3];
extern f32 gTumbleweedBushHitCooldown;
extern ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor;

#endif /* DLLS_OBJECTS_209_TUMBLEWEEDB_H_ */
