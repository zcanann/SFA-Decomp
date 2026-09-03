#ifndef DLLS_OBJECTS_316_XYZANIMATOR_H_
#define DLLS_OBJECTS_316_XYZANIMATOR_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef struct MapBlockData MapBlockData;

typedef enum XyzAnimatorCoordinate {
    XYZ_ANIMATOR_COORD_WORLD_X = 1,
    XYZ_ANIMATOR_COORD_OFFSET_X = 2,
    XYZ_ANIMATOR_COORD_WORLD_Y = 3,
    XYZ_ANIMATOR_COORD_OFFSET_Y = 4,
    XYZ_ANIMATOR_COORD_WORLD_Z = 5,
    XYZ_ANIMATOR_COORD_OFFSET_Z = 6,
} XyzAnimatorCoordinate;

typedef enum XyzAnimatorMode {
    XYZ_ANIMATOR_MODE_ONESHOT = 0,
    XYZ_ANIMATOR_MODE_LOOP = 1,
    XYZ_ANIMATOR_MODE_GATED = 2,
    XYZ_ANIMATOR_MODE_DEFERRED_ONESHOT = 4,
} XyzAnimatorMode;

typedef enum XyzAnimatorObjectGroup {
    XYZ_ANIMATOR_OBJECT_GROUP = 0x51,
} XyzAnimatorObjectGroup;

#define XYZ_ANIMATOR_DRAGON_ROCK_FIREPIPE_IDENT 0x46406

/*
 * The setup fields through mode are evidenced by this TU. The complete record
 * extent after 0x2C is not yet proven, so do not use sizeof(XyzAnimatorPlacement).
 */
typedef struct XyzAnimatorPlacement {
    ObjPlacement base;     /* 0x00 */
    s16 triggerGameBit;    /* 0x18 */
    s16 completionGameBit; /* 0x1A */
    s16 startX;            /* 0x1C */
    s16 startY;            /* 0x1E */
    s16 startZ;            /* 0x20 */
    s16 targetX;           /* 0x22 */
    s16 targetY;           /* 0x24 */
    s16 targetZ;           /* 0x26 */
    s8 blockLayer;         /* 0x28 */
    s8 speedX;             /* 0x29 */
    s8 speedY;             /* 0x2A */
    s8 speedZ;             /* 0x2B */
    u8 mode;               /* 0x2C: XyzAnimatorMode */
} XyzAnimatorPlacement;

/* XyzAnimator_getExtraSize proves the complete 0x50-byte allocation. */
typedef struct XyzAnimatorState {
    int polygonGroupCount; /* 0x00 */
    int vertexCount;       /* 0x04 */
    int displayListCount;  /* 0x08 */
    u8* geometryBuffer;    /* 0x0C: packed XYZ s16 stream */
    u8* posABuffer;        /* 0x10: polygon-group posA s16 stream */
    u8* posBBuffer;        /* 0x14: polygon-group posB s16 stream */
    u8* polygonBuffer0;    /* 0x18 */
    u8* polygonBuffer1;    /* 0x1C */
    u8* polygonBuffer4;    /* 0x20 */
    u8* polygonBuffer5;    /* 0x24 */
    u8* minXBuffer;        /* 0x28 */
    u8* maxXBuffer;        /* 0x2C */
    u8* minYBuffer;        /* 0x30 */
    u8* maxYBuffer;        /* 0x34 */
    u8* minZBuffer;        /* 0x38 */
    u8* maxZBuffer;        /* 0x3C */
    f32 offsetX;           /* 0x40 */
    f32 offsetY;           /* 0x44 */
    f32 offsetZ;           /* 0x48 */
    s8 triggerBitValue;    /* 0x4C */
    s8 passCount;          /* 0x4D */
    u16 loopSfxId;         /* 0x4E */
} XyzAnimatorState;

STATIC_ASSERT(offsetof(XyzAnimatorPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, triggerGameBit) == 0x18);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, completionGameBit) == 0x1A);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, startX) == 0x1C);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, startY) == 0x1E);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, startZ) == 0x20);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, targetX) == 0x22);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, targetY) == 0x24);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, targetZ) == 0x26);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, blockLayer) == 0x28);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, speedX) == 0x29);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, speedY) == 0x2A);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, speedZ) == 0x2B);
STATIC_ASSERT(offsetof(XyzAnimatorPlacement, mode) == 0x2C);

STATIC_ASSERT(offsetof(XyzAnimatorState, polygonGroupCount) == 0x00);
STATIC_ASSERT(offsetof(XyzAnimatorState, vertexCount) == 0x04);
STATIC_ASSERT(offsetof(XyzAnimatorState, displayListCount) == 0x08);
STATIC_ASSERT(offsetof(XyzAnimatorState, geometryBuffer) == 0x0C);
STATIC_ASSERT(offsetof(XyzAnimatorState, posABuffer) == 0x10);
STATIC_ASSERT(offsetof(XyzAnimatorState, posBBuffer) == 0x14);
STATIC_ASSERT(offsetof(XyzAnimatorState, polygonBuffer0) == 0x18);
STATIC_ASSERT(offsetof(XyzAnimatorState, polygonBuffer1) == 0x1C);
STATIC_ASSERT(offsetof(XyzAnimatorState, polygonBuffer4) == 0x20);
STATIC_ASSERT(offsetof(XyzAnimatorState, polygonBuffer5) == 0x24);
STATIC_ASSERT(offsetof(XyzAnimatorState, minXBuffer) == 0x28);
STATIC_ASSERT(offsetof(XyzAnimatorState, maxXBuffer) == 0x2C);
STATIC_ASSERT(offsetof(XyzAnimatorState, minYBuffer) == 0x30);
STATIC_ASSERT(offsetof(XyzAnimatorState, maxYBuffer) == 0x34);
STATIC_ASSERT(offsetof(XyzAnimatorState, minZBuffer) == 0x38);
STATIC_ASSERT(offsetof(XyzAnimatorState, maxZBuffer) == 0x3C);
STATIC_ASSERT(offsetof(XyzAnimatorState, offsetX) == 0x40);
STATIC_ASSERT(offsetof(XyzAnimatorState, offsetY) == 0x44);
STATIC_ASSERT(offsetof(XyzAnimatorState, offsetZ) == 0x48);
STATIC_ASSERT(offsetof(XyzAnimatorState, triggerBitValue) == 0x4C);
STATIC_ASSERT(offsetof(XyzAnimatorState, passCount) == 0x4D);
STATIC_ASSERT(offsetof(XyzAnimatorState, loopSfxId) == 0x4E);
STATIC_ASSERT(sizeof(XyzAnimatorState) == 0x50);

f32 XyzAnimator_getCoordinate(GameObject* obj, u8 coordinate);
void XyzAnimator_captureGeometry(XyzAnimatorPlacement* placement, XyzAnimatorState* state, MapBlockData* blockAddress);
int XyzAnimator_getExtraSize(void);
void XyzAnimator_free(GameObject* obj, int flags);
void XyzAnimator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void XyzAnimator_applyToMapBlock(XyzAnimatorPlacement* placement, XyzAnimatorState* state, MapBlockData* blockAddress);
void XyzAnimator_update(GameObject* obj);
void XyzAnimator_init(GameObject* obj);

extern ObjectDescriptor gXYZAnimatorObjDescriptor;

#endif /* DLLS_OBJECTS_316_XYZANIMATOR_H_ */
