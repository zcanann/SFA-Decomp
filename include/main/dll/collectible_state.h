#ifndef MAIN_DLL_COLLECTIBLE_STATE_H_
#define MAIN_DLL_COLLECTIBLE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * CollectibleState - the obj+0xB8 extra record (0x2B8 bytes) for the
 * collectible / pickup family (dll_00ED_collectible.c). Items dropped by
 * crates/baskets and placed in the world: health food, dust/counter items,
 * etc., distinguished by anim.seqId.
 *
 * Field meanings recovered by live debugging (Dolphin MCP): a crate was
 * broken, the dropped collectible (type 0xB, seqId 11) was traced through
 * proximity-detect -> pickup-message -> collect, and player health was
 * watched rising 4 -> 8 on collect.
 *
 * Fields still prefixed unk are written/read but not yet behaviourally
 * pinned. pathState is the gPathControlInterface bounce/path blob.
 */
typedef struct CollectibleState {
    u8 unk0[0x4 - 0x0];
    f32 scale;             /* 0x04 */
    f32 despawnTimer;      /* 0x08 post-collect fade-out countdown, then Obj_FreeObject */
    u8 unkC;               /* 0x0C */
    u8 unkD;               /* 0x0D */
    u8 unkE[0xF - 0xE];
    u8 unkF;               /* 0x0F nonzero suppresses the active update */
    s16 hideGameBit;       /* 0x10 set on collect so the item stays gone (-1 = none) */
    u8 unk12[0x14 - 0x12];
    s16 visibilityGameBit; /* 0x14 item is active only while this bit is set (-1 = none) */
    u8 unk16[0x18 - 0x16];
    s32 hitRegionId;       /* 0x18 cached ObjHitRegion id (-2 = not yet resolved) */
    u8 unk1C[0x1D - 0x1C];
    u8 bounceTimer;        /* 0x1D loose-motion bounce frames remaining */
    u8 visibilityBitClear; /* 0x1E cached !GameBit_Get(visibilityGameBit) */
    u8 unk1F[0x20 - 0x1F];
    s32 mapId;             /* 0x20 */
    f32 basePosX;          /* 0x24 */
    f32 basePosY;          /* 0x28 */
    f32 basePosZ;          /* 0x2C */
    f32 spinSpeed;         /* 0x30 idle spin applied to anim.rotY, decays each frame */
    s16 spinTimer;         /* 0x34 idle spin re-roll timer */
    u8 useColor;           /* 0x36 */
    u8 pickupLatch;        /* 0x37 bit0: pickup already triggered this approach */
    u8 colorR;             /* 0x38 */
    u8 colorG;             /* 0x39 */
    u8 colorB;             /* 0x3A */
    u8 unk3B[0x3C - 0x3B];
    s16 hideFrames;        /* 0x3C re-show countdown (seqId 0x319) */
    u8 delayedMsgTimer;    /* 0x3E countdown to a deferred in-range message */
    u8 unk3F[0x40 - 0x3F];
    f32 unk40;             /* 0x40 */
    f32 lifetimeTimer;     /* 0x44 auto-despawn timer for uncollected items */
    s16 pickupMsgValue;    /* 0x48 value sent to the player in the pickup message */
    u8 unk4A[0x50 - 0x4A];
    u8 pathState[0x2B1 - 0x50]; /* 0x50 gPathControlInterface bounce/path state */
    u8 bounceHitFlag;      /* 0x2B1 set when loose motion hits a surface */
    u8 unk2B2[0x2B8 - 0x2B2];
} CollectibleState;

STATIC_ASSERT(offsetof(CollectibleState, hideGameBit) == 0x10);
STATIC_ASSERT(offsetof(CollectibleState, visibilityGameBit) == 0x14);
STATIC_ASSERT(offsetof(CollectibleState, mapId) == 0x20);
STATIC_ASSERT(offsetof(CollectibleState, spinSpeed) == 0x30);
STATIC_ASSERT(offsetof(CollectibleState, pathState) == 0x50);
STATIC_ASSERT(sizeof(CollectibleState) == 0x2B8);

/*
 * CollectibleSetup - the per-instance placement/setup record at obj+0x4C
 * (ObjAnimComponent.placementData) for the collectible family. The first
 * 0x18 bytes are the common ObjPlacement head (position/color/mapId); the
 * class-specific tail from 0x18 on configures the pickup: per-axis initial
 * rotation bytes, the hide / visibility / collect / counter game bits, the
 * model bank index, and an optional RGB tint. Read field-by-field in
 * collectible_init / collectible_applyPickup.
 */
typedef struct CollectibleSetup {
    u8 pad0[0x19 - 0x0];
    u8 unkC;            /* 0x19 -> CollectibleState.unkC */
    u8 unkD;            /* 0x1A -> CollectibleState.unkD */
    u8 rotXByte;        /* 0x1B initial anim.rotX (<<8) */
    s16 hideGameBit;    /* 0x1C bit set on collect so the item stays gone */
    s16 collectGameBit; /* 0x1E bit set when the item is picked up (-1 = none) */
    u8 pad20[0x22 - 0x20];
    u8 rotYByte;        /* 0x22 initial anim.rotY (<<8) */
    u8 rotZByte;        /* 0x23 initial anim.rotZ (<<8) */
    s16 visibilityGameBit; /* 0x24 item is active only while this bit is set */
    s8 modelIndex;      /* 0x26 model bank index */
    u8 useColor;        /* 0x27 nonzero applies the RGB tint below */
    u8 colorR;          /* 0x28 */
    u8 colorG;          /* 0x29 */
    u8 colorB;          /* 0x2A */
    u8 pad2B[0x2C - 0x2B];
    s16 counterGameBit; /* 0x2C bit incremented on collect (>0 = active) */
} CollectibleSetup;

STATIC_ASSERT(offsetof(CollectibleSetup, unkC) == 0x19);
STATIC_ASSERT(offsetof(CollectibleSetup, hideGameBit) == 0x1C);
STATIC_ASSERT(offsetof(CollectibleSetup, collectGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CollectibleSetup, rotYByte) == 0x22);
STATIC_ASSERT(offsetof(CollectibleSetup, visibilityGameBit) == 0x24);
STATIC_ASSERT(offsetof(CollectibleSetup, modelIndex) == 0x26);
STATIC_ASSERT(offsetof(CollectibleSetup, colorR) == 0x28);
STATIC_ASSERT(offsetof(CollectibleSetup, counterGameBit) == 0x2C);

#endif /* MAIN_DLL_COLLECTIBLE_STATE_H_ */
