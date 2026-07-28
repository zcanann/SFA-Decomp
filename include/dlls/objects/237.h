#ifndef DLLS_OBJECTS_237_H_
#define DLLS_OBJECTS_237_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

struct ObjAnimUpdateState;

/* ObjGroup slot containing the collectible object family. */
#define COLLECTIBLE_OBJECT_GROUP 4

/* Health-refill collectible sequence IDs. */
#define COLLECTIBLE_ITEM_ENERGY_EGG 0xB   /* large refill: +4 health */
#define COLLECTIBLE_ITEM_APPLE      0x3CD /* small refill: +2 health */

/*
 * Per-instance state for the collectible family. The path-control interface
 * owns the opaque region beginning at pathState.
 */
typedef struct CollectibleState {
    f32 playerDistance;           /* 0x00: most recent horizontal distance to the player */
    f32 pickupRadius;             /* 0x04 */
    f32 despawnTimer;             /* 0x08: post-collect fade-out countdown */
    u8 unk0C;                     /* 0x0C */
    u8 unk0D;                     /* 0x0D */
    u8 pad0E;                     /* 0x0E */
    u8 disabled;                  /* 0x0F */
    s16 hideGameBit;              /* 0x10: set on collection; -1 = none */
    u8 pad12[2];                  /* 0x12 */
    s16 visibilityGameBit;        /* 0x14: active while set; -1 = none */
    u8 pad16[2];                  /* 0x16 */
    s32 hitRegionId;              /* 0x18: -2 until resolved */
    u8 pad1C;                     /* 0x1C */
    u8 bounceTimer;               /* 0x1D */
    u8 visibilityBitClear;        /* 0x1E */
    u8 pad1F;                     /* 0x1F */
    s32 mapId;                    /* 0x20 */
    f32 basePosX;                 /* 0x24 */
    f32 basePosY;                 /* 0x28 */
    f32 basePosZ;                 /* 0x2C */
    f32 spinSpeed;                /* 0x30 */
    s16 spinTimer;                /* 0x34 */
    u8 useColor;                  /* 0x36 */
    u8 pickupLatch;               /* 0x37: bit 0 prevents duplicate pickup */
    u8 colorR;                    /* 0x38 */
    u8 colorG;                    /* 0x39 */
    u8 colorB;                    /* 0x3A */
    u8 pad3B;                     /* 0x3B */
    s16 hideFrames;               /* 0x3C */
    u8 delayedMsgTimer;           /* 0x3E */
    u8 pad3F;                     /* 0x3F */
    f32 unk40;                    /* 0x40 */
    f32 lifetimeTimer;            /* 0x44 */
    s16 pickupMsgValue;           /* 0x48 */
    u8 pad4A[6];                  /* 0x4A */
    u8 pathState[0xB8 - 0x50];    /* 0x50 */
    f32 bounceNormalX;            /* 0xB8 */
    f32 bounceNormalY;            /* 0xBC */
    f32 bounceNormalZ;            /* 0xC0 */
    u8 pathStateC4[0x2B1 - 0xC4]; /* 0xC4 */
    s8 bounceHitFlag;             /* 0x2B1 */
    u8 pad2B2[6];                 /* 0x2B2 */
} CollectibleState;

STATIC_ASSERT(offsetof(CollectibleState, playerDistance) == 0x0);
STATIC_ASSERT(offsetof(CollectibleState, pickupRadius) == 0x4);
STATIC_ASSERT(offsetof(CollectibleState, despawnTimer) == 0x8);
STATIC_ASSERT(offsetof(CollectibleState, unk0C) == 0xC);
STATIC_ASSERT(offsetof(CollectibleState, unk0D) == 0xD);
STATIC_ASSERT(offsetof(CollectibleState, pad0E) == 0xE);
STATIC_ASSERT(offsetof(CollectibleState, disabled) == 0xF);
STATIC_ASSERT(offsetof(CollectibleState, hideGameBit) == 0x10);
STATIC_ASSERT(offsetof(CollectibleState, pad12) == 0x12);
STATIC_ASSERT(offsetof(CollectibleState, visibilityGameBit) == 0x14);
STATIC_ASSERT(offsetof(CollectibleState, pad16) == 0x16);
STATIC_ASSERT(offsetof(CollectibleState, hitRegionId) == 0x18);
STATIC_ASSERT(offsetof(CollectibleState, pad1C) == 0x1C);
STATIC_ASSERT(offsetof(CollectibleState, bounceTimer) == 0x1D);
STATIC_ASSERT(offsetof(CollectibleState, visibilityBitClear) == 0x1E);
STATIC_ASSERT(offsetof(CollectibleState, pad1F) == 0x1F);
STATIC_ASSERT(offsetof(CollectibleState, mapId) == 0x20);
STATIC_ASSERT(offsetof(CollectibleState, basePosX) == 0x24);
STATIC_ASSERT(offsetof(CollectibleState, basePosY) == 0x28);
STATIC_ASSERT(offsetof(CollectibleState, basePosZ) == 0x2C);
STATIC_ASSERT(offsetof(CollectibleState, spinSpeed) == 0x30);
STATIC_ASSERT(offsetof(CollectibleState, spinTimer) == 0x34);
STATIC_ASSERT(offsetof(CollectibleState, useColor) == 0x36);
STATIC_ASSERT(offsetof(CollectibleState, pickupLatch) == 0x37);
STATIC_ASSERT(offsetof(CollectibleState, colorR) == 0x38);
STATIC_ASSERT(offsetof(CollectibleState, colorG) == 0x39);
STATIC_ASSERT(offsetof(CollectibleState, colorB) == 0x3A);
STATIC_ASSERT(offsetof(CollectibleState, pad3B) == 0x3B);
STATIC_ASSERT(offsetof(CollectibleState, hideFrames) == 0x3C);
STATIC_ASSERT(offsetof(CollectibleState, delayedMsgTimer) == 0x3E);
STATIC_ASSERT(offsetof(CollectibleState, pad3F) == 0x3F);
STATIC_ASSERT(offsetof(CollectibleState, unk40) == 0x40);
STATIC_ASSERT(offsetof(CollectibleState, lifetimeTimer) == 0x44);
STATIC_ASSERT(offsetof(CollectibleState, pickupMsgValue) == 0x48);
STATIC_ASSERT(offsetof(CollectibleState, pad4A) == 0x4A);
STATIC_ASSERT(offsetof(CollectibleState, pathState) == 0x50);
STATIC_ASSERT(offsetof(CollectibleState, bounceNormalX) == 0xB8);
STATIC_ASSERT(offsetof(CollectibleState, bounceNormalY) == 0xBC);
STATIC_ASSERT(offsetof(CollectibleState, bounceNormalZ) == 0xC0);
STATIC_ASSERT(offsetof(CollectibleState, pathStateC4) == 0xC4);
STATIC_ASSERT(offsetof(CollectibleState, bounceHitFlag) == 0x2B1);
STATIC_ASSERT(offsetof(CollectibleState, pad2B2) == 0x2B2);
STATIC_ASSERT(sizeof(CollectibleState) == 0x2B8);

/*
 * The 0x30-byte setup record shared by the whole pickup family. Spawners
 * (LargeCrate, SmallBasket, MagicPlant, 247, 462, engine/25) allocate it
 * and write the same block - unk1A = 0x14, the three game bits set to -1
 * and the base position - before Obj_SetupObject; the spawned object's
 * init reads modelIndex and spawnMode back out of it.
 */
typedef struct CollectibleSetup {
    ObjPlacement base;     /* 0x00 */
    u8 pad18;              /* 0x18 */
    u8 unk19;              /* 0x19 -> CollectibleState.unk0C */
    u8 unk1A;              /* 0x1A -> CollectibleState.unk0D */
    u8 rotXByte;           /* 0x1B initial anim.rotX (<<8) */
    s16 hideGameBit;       /* 0x1C bit set on collect so the item stays gone */
    s16 collectGameBit;    /* 0x1E bit set when the item is picked up (-1 = none) */
    u8 pad20[2];           /* 0x20 */
    u8 rotYByte;           /* 0x22 initial anim.rotY (<<8) */
    u8 rotZByte;           /* 0x23 initial anim.rotZ (<<8) */
    s16 visibilityGameBit; /* 0x24 item is active only while this bit is set */
    u8 modelIndex;         /* 0x26 model bank index */
    u8 useColor;           /* 0x27 nonzero applies the RGB tint below */
    u8 colorR;             /* 0x28 */
    u8 colorG;             /* 0x29 */
    u8 colorB;             /* 0x2A */
    u8 pad2B;              /* 0x2B */
    s16 counterGameBit;    /* 0x2C bit incremented on collect (>0 = active) */
    s16 spawnMode;         /* 0x2E reward-spawn variant selected by the spawner */
} CollectibleSetup;

typedef struct CollectibleModelSetup {
    u8 pad00[2];        /* 0x00 */
    s16 pickupCategory; /* 0x02 */
    u8 pad04[4];        /* 0x04 */
    s8 pickupRadius;    /* 0x08 */
} CollectibleModelSetup;

STATIC_ASSERT(offsetof(CollectibleSetup, base) == 0x0);
STATIC_ASSERT(offsetof(CollectibleSetup, pad18) == 0x18);
STATIC_ASSERT(offsetof(CollectibleSetup, unk19) == 0x19);
STATIC_ASSERT(offsetof(CollectibleSetup, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(CollectibleSetup, rotXByte) == 0x1B);
STATIC_ASSERT(offsetof(CollectibleSetup, hideGameBit) == 0x1C);
STATIC_ASSERT(offsetof(CollectibleSetup, collectGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CollectibleSetup, pad20) == 0x20);
STATIC_ASSERT(offsetof(CollectibleSetup, rotYByte) == 0x22);
STATIC_ASSERT(offsetof(CollectibleSetup, rotZByte) == 0x23);
STATIC_ASSERT(offsetof(CollectibleSetup, visibilityGameBit) == 0x24);
STATIC_ASSERT(offsetof(CollectibleSetup, modelIndex) == 0x26);
STATIC_ASSERT(offsetof(CollectibleSetup, useColor) == 0x27);
STATIC_ASSERT(offsetof(CollectibleSetup, colorR) == 0x28);
STATIC_ASSERT(offsetof(CollectibleSetup, colorG) == 0x29);
STATIC_ASSERT(offsetof(CollectibleSetup, colorB) == 0x2A);
STATIC_ASSERT(offsetof(CollectibleSetup, pad2B) == 0x2B);
STATIC_ASSERT(offsetof(CollectibleSetup, counterGameBit) == 0x2C);
STATIC_ASSERT(offsetof(CollectibleSetup, spawnMode) == 0x2E);
STATIC_ASSERT(sizeof(CollectibleSetup) == 0x30);

STATIC_ASSERT(offsetof(CollectibleModelSetup, pad00) == 0x0);
STATIC_ASSERT(offsetof(CollectibleModelSetup, pickupCategory) == 0x2);
STATIC_ASSERT(offsetof(CollectibleModelSetup, pad04) == 0x4);
STATIC_ASSERT(offsetof(CollectibleModelSetup, pickupRadius) == 0x8);

/*
 * gCollectibleObjDescriptor from slot02 onwards: the export table the crate and
 * basket objects reach through child->anim.dll to launch a dropped collectible.
 */
typedef struct CollectibleInterface {
    void* pad00[11];
    void (*startBounceMotion)(GameObject* collectible, f32 velocityX, f32 velocityY, f32 velocityZ);
} CollectibleInterface;

STATIC_ASSERT(offsetof(CollectibleInterface, startBounceMotion) == 0x2C);

void collectible_setPosition(GameObject* obj, f32 x, f32 y, f32 z);
void collectible_startBounceMotion(GameObject* obj, f32 velocityX, f32 velocityY, f32 velocityZ);
u8 collectible_getVisibilityBitClear(GameObject* obj);
void collectible_setVisibilityBitClear(GameObject* obj, u32 clear);
int collectible_getHitRegionId(GameObject* obj);
void collectible_setDisabled(GameObject* obj, int disabled);
int collectible_getIsHidden(GameObject* obj);
void collectible_applyPickup(GameObject* obj);
void collectible_updateLooseMotion(GameObject* obj);
void collectible_updateIdleMotion(GameObject* obj);
int collectible_SeqFn(GameObject* obj, int unused, struct ObjAnimUpdateState* animUpdate);
void collectible_checkProximityPickup(GameObject* obj, u8* state);
int collectible_getExtraSize(void);
int collectible_getObjectTypeId(void);
void collectible_free(GameObject* obj);
void collectible_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible);
void collectible_hitDetect(GameObject* obj);
void collectible_update(GameObject* obj);
void collectible_init(GameObject* obj, CollectibleSetup* setup);
void collectible_release(void);
void collectible_initialise(void);

extern ObjectDescriptor17 gCollectibleObjDescriptor;

#endif /* DLLS_OBJECTS_237_H_ */
