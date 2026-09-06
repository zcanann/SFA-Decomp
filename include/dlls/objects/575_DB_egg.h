#ifndef DLLS_OBJECTS_575_DB_EGG_H_
#define DLLS_OBJECTS_575_DB_EGG_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/dll/curve_walker.h"

/* dbegg_getExtraSize() allocates the complete 0x124-byte state block. */
typedef struct DbEggState {
    f32 waterOffset;      /* float-height offset above water */
    RomCurveWalker curve; /* 0x004: rom-curve walker record (state+4 to gRomCurveInterface) */
    f32 launchVelX;       /* 0x10C: launch velocity vec3, set by dbegg_setLaunchVelocity, applied
        to anim.velocity when the egg is thrown */
    f32 launchVelY;       /* 0x110 */
    f32 launchVelZ;       /* 0x114 */
    u8 mode;              /* 0x118 */
    u8 flags119;          /* bits 1/2/4/8/0x10 */
    u8 unk11A[2];
    s16 msg11C; /* 0x11C: 3-word message payload sent via ObjMsg */
    s16 msg11E;
    f32 msg120;
} DbEggState;

STATIC_ASSERT(offsetof(DbEggState, waterOffset) == 0x000);
STATIC_ASSERT(offsetof(DbEggState, curve) == 0x004);
STATIC_ASSERT(offsetof(DbEggState, launchVelX) == 0x10C);
STATIC_ASSERT(offsetof(DbEggState, launchVelY) == 0x110);
STATIC_ASSERT(offsetof(DbEggState, launchVelZ) == 0x114);
STATIC_ASSERT(offsetof(DbEggState, mode) == 0x118);
STATIC_ASSERT(offsetof(DbEggState, flags119) == 0x119);
STATIC_ASSERT(offsetof(DbEggState, unk11A) == 0x11A);
STATIC_ASSERT(offsetof(DbEggState, msg11C) == 0x11C);
STATIC_ASSERT(offsetof(DbEggState, msg11E) == 0x11E);
STATIC_ASSERT(offsetof(DbEggState, msg120) == 0x120);
STATIC_ASSERT(sizeof(DbEggState) == 0x124);

typedef struct DbeggPlacement {
    ObjPlacement base;    /* 0x00 */
    u8 pad18;             /* 0x18 */
    u8 forceRadiusByte;   /* 0x19 */
    u8 speedScaleByte;    /* 0x1A: root-motion scale in 1/64 units */
    u8 facingAngleByte;   /* 0x1B: initial anim.rotX (<<8) */
    s16 triggerGameBit;   /* 0x1C: set once the egg is delivered; also selects the start mode */
    s16 secondaryGameBit; /* 0x1E: set when the egg reaches its target */
    s16 unk20;            /* 0x20 */
    u8 pad22[0x24 - 0x22];
    s16 activateGameBit; /* 0x24: gates the launch mode */
    u8 behaviorMode;     /* 0x26 */
    u8 pad27[0x2B - 0x27];
    u8 unk2B;           /* 0x2B */
    s16 counterGameBit; /* 0x2C: bit incremented on delivery (>0 = active) */
    s8 unk2E;           /* 0x2E */
} DbeggPlacement;

STATIC_ASSERT(offsetof(DbeggPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(DbeggPlacement, forceRadiusByte) == 0x19);
STATIC_ASSERT(offsetof(DbeggPlacement, speedScaleByte) == 0x1A);
STATIC_ASSERT(offsetof(DbeggPlacement, facingAngleByte) == 0x1B);
STATIC_ASSERT(offsetof(DbeggPlacement, triggerGameBit) == 0x1C);
STATIC_ASSERT(offsetof(DbeggPlacement, secondaryGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DbeggPlacement, unk20) == 0x20);
STATIC_ASSERT(offsetof(DbeggPlacement, activateGameBit) == 0x24);
STATIC_ASSERT(offsetof(DbeggPlacement, behaviorMode) == 0x26);
STATIC_ASSERT(offsetof(DbeggPlacement, unk2B) == 0x2B);
STATIC_ASSERT(offsetof(DbeggPlacement, counterGameBit) == 0x2C);
STATIC_ASSERT(offsetof(DbeggPlacement, unk2E) == 0x2E);
STATIC_ASSERT(sizeof(DbeggPlacement) == 0x30);

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
void dbegg_computeFlocking(GameObject* obj, f32* vel);

extern ObjectDescriptor12 gDB_eggObjDescriptor;

#endif /* DLLS_OBJECTS_575_DB_EGG_H_ */
