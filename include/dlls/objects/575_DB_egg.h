#ifndef DLLS_OBJECTS_575_DB_EGG_H_
#define DLLS_OBJECTS_575_DB_EGG_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/dll/curve_walker.h"

#define DBEGG_OBJGROUP 0x24

/* dbegg_getExtraSize() allocates the complete 0x124-byte state block. */
typedef struct DbEggState {
    f32 waterOffset;      /* float-height offset above water */
    RomCurveWalker curve; /* 0x004: rom-curve walker record (state+4 to gRomCurveInterface) */
    f32 launchVelX;       /* 0x10C: launch velocity vec3, set by dbegg_setLaunchVelocity, applied
        to anim.velocity when the egg is thrown */
    f32 launchVelY;       /* 0x110 */
    f32 launchVelZ;       /* 0x114 */
    u8 mode;              /* 0x118 */
    u8 flags;             /* 0x119: DBEGG_FLAG_* */
    u8 unk11A[2];
    s16 triggerGameBit;        /* 0x11C: head of the eight-byte pickup-message payload; -1 skips the gate */
    s16 pickupMessageValue;    /* 0x11E: copied to player state; downstream meaning unknown */
    f32 pickupMessageArgument; /* 0x120: initialized to 1.0; consumer meaning unknown */
} DbEggState;

STATIC_ASSERT(offsetof(DbEggState, waterOffset) == 0x000);
STATIC_ASSERT(offsetof(DbEggState, curve) == 0x004);
STATIC_ASSERT(offsetof(DbEggState, launchVelX) == 0x10C);
STATIC_ASSERT(offsetof(DbEggState, launchVelY) == 0x110);
STATIC_ASSERT(offsetof(DbEggState, launchVelZ) == 0x114);
STATIC_ASSERT(offsetof(DbEggState, mode) == 0x118);
STATIC_ASSERT(offsetof(DbEggState, flags) == 0x119);
STATIC_ASSERT(offsetof(DbEggState, unk11A) == 0x11A);
STATIC_ASSERT(offsetof(DbEggState, triggerGameBit) == 0x11C);
STATIC_ASSERT(offsetof(DbEggState, pickupMessageValue) == 0x11E);
STATIC_ASSERT(offsetof(DbEggState, pickupMessageArgument) == 0x120);
STATIC_ASSERT(sizeof(DbEggState) == 0x124);

/* Reader view only: the complete EN serialized extent is not established.
 * Do not allocate or copy placements using sizeof this prefix. */
typedef struct DbEggPlacementPrefix {
    ObjPlacement base;    /* 0x00 */
    u8 pad18[2];          /* 0x18 */
    u8 speedScaleByte;    /* 0x1A: root-motion scale in 1/64 units */
    u8 facingAngleByte;   /* 0x1B: initial anim.rotX (<<8) */
    s16 triggerGameBit;   /* 0x1C: set once the egg is delivered; also selects the start mode */
    s16 secondaryGameBit; /* 0x1E: set when the egg reaches its target */
    u8 pad20[0x24 - 0x20];
    s16 activateGameBit; /* 0x24: gates the launch mode */
    u8 behaviorMode;     /* 0x26 */
    u8 pad27[0x2C - 0x27];
    s16 counterGameBit; /* 0x2C: bit incremented on delivery (>0 = active) */
} DbEggPlacementPrefix;

STATIC_ASSERT(offsetof(DbEggPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(DbEggPlacementPrefix, speedScaleByte) == 0x1A);
STATIC_ASSERT(offsetof(DbEggPlacementPrefix, facingAngleByte) == 0x1B);
STATIC_ASSERT(offsetof(DbEggPlacementPrefix, triggerGameBit) == 0x1C);
STATIC_ASSERT(offsetof(DbEggPlacementPrefix, secondaryGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DbEggPlacementPrefix, activateGameBit) == 0x24);
STATIC_ASSERT(offsetof(DbEggPlacementPrefix, behaviorMode) == 0x26);
STATIC_ASSERT(offsetof(DbEggPlacementPrefix, counterGameBit) == 0x2C);

typedef struct DbEggIntPair {
    s32 a;
    s32 b;
} DbEggIntPair;

STATIC_ASSERT(offsetof(DbEggIntPair, a) == 0x00);
STATIC_ASSERT(offsetof(DbEggIntPair, b) == 0x04);
STATIC_ASSERT(sizeof(DbEggIntPair) == 0x08);

int dbegg_setLaunchVelocity(GameObject* obj, f32* velocity);
int dbegg_isActive(GameObject* obj);
int dbegg_getExtraSize(void);
int dbegg_getObjectTypeId(void);
void dbegg_free(GameObject* obj);
void dbegg_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void dbegg_hitDetect(GameObject* obj);
void dbegg_update(GameObject* obj);
void dbegg_init(GameObject* obj);
void dbegg_release(void);
void dbegg_initialise(void);
void dbegg_setupFromDef(GameObject* obj, u8* state);
void dbegg_processMessages(GameObject* obj);
int dbegg_probeSurface(GameObject* obj, f32* out, f32 offsetX, f32 offsetZ, int flag);
void dbegg_computeWaterCurrent(GameObject* obj, f32* vel);

extern ObjectDescriptor12 gDB_eggObjDescriptor;

#endif /* DLLS_OBJECTS_575_DB_EGG_H_ */
