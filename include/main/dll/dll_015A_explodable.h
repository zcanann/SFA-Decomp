#ifndef MAIN_DLL_EXPLODABLE_H_
#define MAIN_DLL_EXPLODABLE_H_

#include "main/dll/drexplodable_types.h"
#include "main/obj_placement.h"

/*
 * Placement/def record for an explodable prop. Embeds the common ObjPlacement
 * head (posX/posY/posZ/mapId etc.) the map loader hands to explodable_init /
 * explodable_update, then carries the prop's class-specific fields - matching
 * the <Family>Placement convention used by the other object DLLs (e.g.
 * CntHitObjectSetup). The old pad0[0x1A] swallowed this 0x18-byte head plus the
 * 2-byte class slot at 0x18.
 */
typedef struct ExplodablePlacement
{
    ObjPlacement base;   /* 0x00: common placement head (position / mapId) */
    u8 fragmentCount;    /* 0x18: number of fragments to spawn (0 -> 1) */
    u8 pad19[0x1A - 0x19];
    s16 rotX;            /* 0x1A: prop orientation */
    s16 rotY;            /* 0x1C */
    s16 rotZ;            /* 0x1E */
    s16 originX;         /* 0x20: launch-spread reference origin (local space) */
    s16 originY;         /* 0x22 */
    s16 originZ;         /* 0x24 */
    u8 pad26[0x2C - 0x26];
    s16 launchForce;     /* 0x2C: fragment launch speed scale */
    s16 fragmentHeight;  /* 0x2E: per-fragment height override (0 = none) */
    s16 unk30;           /* 0x30: secondary launch-spread scale */
    u8 pad32[0x38 - 0x32];
    u16 launchDelayBase; /* 0x38: base for the per-fragment launch-delay roll */
    u8 pad3A[0x3E - 0x3B];
    s8 scaleParam;       /* 0x3D: prop scale (defaults to 0x14) */
    s16 doneGameBit;     /* 0x3E: raised once the prop has broken */
    s16 activateGameBit; /* 0x40: triggers the break (live-verified) */
    u8 pad42[0x48 - 0x42];
} ExplodablePlacement;

STATIC_ASSERT(offsetof(ExplodablePlacement, rotX) == 0x1A);
STATIC_ASSERT(offsetof(ExplodablePlacement, originX) == 0x20);
STATIC_ASSERT(offsetof(ExplodablePlacement, launchForce) == 0x2C);
STATIC_ASSERT(offsetof(ExplodablePlacement, launchDelayBase) == 0x38);
STATIC_ASSERT(offsetof(ExplodablePlacement, scaleParam) == 0x3D);
STATIC_ASSERT(offsetof(ExplodablePlacement, doneGameBit) == 0x3E);
STATIC_ASSERT(offsetof(ExplodablePlacement, activateGameBit) == 0x40);
STATIC_ASSERT(sizeof(ExplodablePlacement) == 0x48);

/*
 * One row of the break-recipe table (gExplodableBreakRecipeTable), keyed on the prop's seqId.
 * Selects the spawned fragment object type, break sfx, and mode/behaviour flags.
 */
typedef struct GasVentTableEntry
{
    int key;
    int objType;
    int sfx;
    u8 mode;
    u8 flags;
    u8 pad[2];
} GasVentTableEntry;

/*
 * The 0x44-byte spawn-setup buffer explodable_spawnFragmentObject fills in and
 * hands to Obj_SetupObject to create one fragment object. Velocity/spin fields
 * are packed as the engine's s16 fixed-point (written from scaled f32).
 */
typedef struct ExplodableFragmentSetup
{
    s16 seqId;            /* 0x00: fragment object type */
    u8 pad02[2];
    u8 unk04;             /* 0x04: const 2 */
    u8 unk05;             /* 0x05: const 1 */
    u8 unk06;             /* 0x06: const 0xff */
    u8 unk07;             /* 0x07: const 0xff */
    f32 posX;             /* 0x08 */
    f32 posY;             /* 0x0c */
    f32 posZ;             /* 0x10 */
    u8 pad14[0x18 - 0x14];
    u8 fragmentIndex;     /* 0x18 */
    u8 pad19[0x1A - 0x19];
    s16 rotX;             /* 0x1a */
    s16 rotY;             /* 0x1c */
    s16 rotZ;             /* 0x1e */
    u16 velX;             /* 0x20 */
    u16 velY;             /* 0x22 */
    u16 velZ;             /* 0x24 */
    u16 unk26;            /* 0x26: secondary velocity vector */
    u16 unk28;            /* 0x28 */
    u16 unk2A;            /* 0x2a */
    u16 spinX;            /* 0x2c */
    u16 spinY;            /* 0x2e */
    u16 spinZ;            /* 0x30 */
    u16 unk32;            /* 0x32: secondary spin vector */
    u16 unk34;            /* 0x34 */
    u16 unk36;            /* 0x36 */
    u16 launchDelayBase;  /* 0x38 */
    u16 height;           /* 0x3a */
    u8 pad3C[1];
    s8 scale;             /* 0x3d */
    u8 pad3E[0x44 - 0x3E];
} ExplodableFragmentSetup;

STATIC_ASSERT(offsetof(ExplodableFragmentSetup, posX) == 0x08);
STATIC_ASSERT(offsetof(ExplodableFragmentSetup, fragmentIndex) == 0x18);
STATIC_ASSERT(offsetof(ExplodableFragmentSetup, rotX) == 0x1A);
STATIC_ASSERT(offsetof(ExplodableFragmentSetup, velX) == 0x20);
STATIC_ASSERT(offsetof(ExplodableFragmentSetup, spinX) == 0x2C);
STATIC_ASSERT(offsetof(ExplodableFragmentSetup, height) == 0x3A);
STATIC_ASSERT(offsetof(ExplodableFragmentSetup, scale) == 0x3D);
STATIC_ASSERT(sizeof(ExplodableFragmentSetup) == 0x44);

void explodable_render(void);
int explodable_getExtraSize(void);
void explodable_free(int obj, int flag);
void explodable_update(int obj);
void explodable_init(int obj, int setup);
int explodable_spawnFragmentObject(int obj, int objType, int chunkSrc, int fragmentIndex);
void explodable_buildFragments(int obj, int def, int skipCentroid, int state);
void explodable_computeFragmentLaunch(int obj, int chunkSlot, int def);

#endif /* MAIN_DLL_EXPLODABLE_H_ */
