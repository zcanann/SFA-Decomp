#ifndef MAIN_EXPGFX_INTERNAL_H_
#define MAIN_EXPGFX_INTERNAL_H_

#include "ghidra_import.h"

#define EXPGFX_POOL_COUNT 0x50
#define EXPGFX_POOL_GROUP_COUNT (EXPGFX_POOL_COUNT / 8)
#define EXPGFX_POOL_SEARCH_BATCH_SIZE 5
#define EXPGFX_POOL_SEARCH_BATCH_COUNT (EXPGFX_POOL_COUNT / EXPGFX_POOL_SEARCH_BATCH_SIZE)
#define EXPGFX_SLOTS_PER_POOL 0x19
#define EXPGFX_SLOT_SIZE 0xA0
#define EXPGFX_POOL_BYTES (EXPGFX_SLOTS_PER_POOL * EXPGFX_SLOT_SIZE)
#define EXPGFX_SPAWN_CONFIG_PREFIX_BYTES 0x60
#define EXPGFX_RESOURCE_TABLE_COUNT 0x20
#define EXPGFX_EXPTAB_ENTRY_COUNT EXPGFX_POOL_COUNT
#define EXPGFX_INVALID_TABLE_INDEX -1
#define EXPGFX_INVALID_POOL_INDEX -1
#define EXPGFX_INVALID_SLOT_TYPE -1
#define EXPGFX_INVALID_SEQUENCE_ID -1
#define EXPGFX_EXPTAB_REFCOUNT_MAX 0xFFFF
#define EXPGFX_TABLE_ENTRY_SHIFT 4
#define EXPGFX_TABLE_ENTRY_SIZE (1 << EXPGFX_TABLE_ENTRY_SHIFT)
#define EXPGFX_SLOT_TABLE_INDEX_MASK 0x7F
#define EXPGFX_BYTE_VALUE_MASK 0xff
#define EXPGFX_SEQUENCE_COUNTER_MAX 30000
#define EXPGFX_BOUNDS_TEMPLATE_SIZE sizeof(ExpgfxBounds)

#define EXPGFX_RESOURCE_TABLE_OFFSET 0x000
#define EXPGFX_POOL_BOUNDS_OFFSET 0x200
#define EXPGFX_EXPTAB_OFFSET 0x980
#define EXPGFX_EXPTAB_TEXTURE_RESOURCE_OFFSET 0x988
#define EXPGFX_EXPTAB_REFCOUNT_OFFSET 0x98C
#define EXPGFX_POOL_SOURCE_MODES_OFFSET 0xE80
#define EXPGFX_POOL_SOURCE_IDS_OFFSET 0xED0
#define EXPGFX_TRACKED_SOURCE_FRAME_MASKS_OFFSET 0x1010
#define EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET 0x1020
#define EXPGFX_POOL_ACTIVE_COUNTS_OFFSET 0x1070
#define EXPGFX_POOL_ACTIVE_MASKS_OFFSET 0x10C0
#define EXPGFX_SLOT_POOL_BASES_OFFSET 0x1200

#define EXPGFX_STATIC_POOL_SLOT_TYPE_IDS_OFFSET 0x30
#define EXPGFX_STATIC_POOL_FRAME_FLAGS_OFFSET 0xD0
#define EXPGFX_STATIC_QUAD_TEMPLATE_A_OFFSET 0x150
#define EXPGFX_STATIC_QUAD_TEMPLATE_B_OFFSET 0x168

/*
 * Flag names describe observed behavior in expgfx_addremove. Keep them local
 * until neighboring constructors and asset tables prove the original terms.
 */
#define EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_A 0x00000002
#define EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B 0x00000004
#define EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY 0x00000008
#define EXPGFX_BEHAVIOR_FLIP_TEX0_T 0x00000040
#define EXPGFX_BEHAVIOR_FLIP_TEX1_T 0x00000080
#define EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A 0x00020000
#define EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE 0x00040000
#define EXPGFX_BEHAVIOR_SCALE_FROM_ZERO 0x00100000
#define EXPGFX_BEHAVIOR_COPY_ATTACHED_SOURCE 0x00200000
#define EXPGFX_BEHAVIOR_FAST_Y_RESPONSE 0x01000000
#define EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_B 0x04000000
#define EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A 0x08000000
#define EXPGFX_BEHAVIOR_SOURCE_MODE_FLAG 0x20000000
#define EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY 0x40000000

#define EXPGFX_RENDER_INIT_QUAD 0x00000002
#define EXPGFX_RENDER_BACKDATE_MOTION 0x00000008
#define EXPGFX_RENDER_AIM_AT_ACTOR 0x00000010
#define EXPGFX_RENDER_OVERRIDE_COLORS 0x00000020
#define EXPGFX_RENDER_SCALE_OVER_LIFETIME 0x00002000
#define EXPGFX_RENDER_PHASE_ROTATE_A 0x04000000
#define EXPGFX_RENDER_PHASE_ROTATE_B 0x08000000

#define EXPGFX_SLOT_STATE_FRAME_PARITY 0x01
#define EXPGFX_SLOT_STATE_QUAD_READY 0x02
#define EXPGFX_SLOT_STATE_INIT_PHASE_MASK 0x0C
#define EXPGFX_TRACKED_POOL_MASK_WORD_STRIDE 2
#define EXPGFX_SOURCE_FRAME_STATE_NONE 0
#define EXPGFX_SOURCE_FRAME_STATE_A 1
#define EXPGFX_SOURCE_FRAME_STATE_B 2
#define EXPGFX_SOURCE_FRAME_STATE_MIXED 3
#define EXPGFX_POOL_SOURCE_MODE_STANDALONE 0
#define EXPGFX_POOL_SOURCE_MODE_SOURCE_OFFSET 1
#define EXPGFX_SOURCE_OBJTYPE_MATCH_ALL 0xD4
#define EXPGFX_QUAD_TEXCOORD_MAX 0x80
#define EXPGFX_QUEUE_DEPTH_SLOT_TYPE_MASK 0x21

typedef struct ExpgfxBounds {
  float minX;
  float maxX;
  float minY;
  float maxY;
  float minZ;
  float maxZ;
} ExpgfxBounds;

typedef struct ExpgfxCurrentSource {
  int sourceId;
  int sourceMode;
} ExpgfxCurrentSource;

typedef struct ExpgfxSourceObject {
  u8 pad00[0x46];
  /* Type 0xD4 updates frame flags for every tracked pool, not just pointer matches. */
  s16 objType;
} ExpgfxSourceObject;

/*
 * Retail warning strings call this structure "exptab". The key fields are
 * still only partially understood, but the table's role and lifetime rules
 * are stable enough to stop treating it as raw integer arrays.
 */
typedef struct ExpgfxTableEntry {
  int key0;
  int key1;
  int textureOrResource;
  u16 refCount;
  s16 slotType;
} ExpgfxTableEntry;

/*
 * Some spawn requests materialize an inline attached-source block after the
 * fixed config prefix. That state can seed source vectors, source positions,
 * and inherited velocity for the spawned effect.
 */
typedef struct ExpgfxAttachedSourceState {
  s16 sourceVecX;
  s16 sourceVecY;
  s16 sourceVecZ;
  u8 pad06[0x08 - 0x06];
  int sourcePosXBits;
  int sourcePosYBits;
  int sourcePosZBits;
  int sourcePosWBits;
  float velocityX;
  float velocityY;
  float velocityZ;
  int tableKey1;
} ExpgfxAttachedSourceState;

/*
 * Spawn requests are sourced from the current expgfx context. Not every word
 * is understood yet, but the stable fields are worth naming directly.
 */
typedef struct ExpgfxSpawnConfig {
  void *attachedSource;
  void *velocitySource;
  u8 pad08[0x0C - 0x08];
  s16 sourceVecX;
  s16 sourceVecY;
  s16 sourceVecZ;
  u8 pad12[0x14 - 0x12];
  int sourcePosXBits;
  int sourcePosYBits;
  int sourcePosZBits;
  int sourcePosWBits;
  float velocityX;
  float velocityY;
  float velocityZ;
  int startPosXBits;
  int startPosYBits;
  int startPosZBits;
  float scale;
  u8 pad40[0x42 - 0x40];
  s16 tableKeyType;
  u32 behaviorFlags;
  u32 renderFlags;
  u32 overrideColor0;
  u32 overrideColor1;
  u32 overrideColor2;
  u16 colorByte0Hi;
  u16 colorByte1Hi;
  u16 colorByte2Hi;
  u8 pad5E[0x60 - 0x5E];
  u8 initialStateByte;
  u8 linkGroup;
} ExpgfxSpawnConfig;

typedef struct ExpgfxResourceEntry {
  void *resource;
  s32 evictionScore;
  s32 tableKeyType;
  u32 wordC;
} ExpgfxResourceEntry;

typedef struct ExpgfxResourceHandle {
  u8 pad00[0x0E];
  u16 refCount;
  u8 pad10[0x14 - 0x10];
  u16 linkGroup;
} ExpgfxResourceHandle;

typedef union ExpgfxSlotStateBits {
  u8 value;
  struct {
    u8 padHi : 4;
    u8 initPhase : 2;
    u8 quadReady : 1;
    u8 frameParity : 1;
  } bits;
} ExpgfxSlotStateBits;

typedef struct ExpgfxSlot {
  u8 pad00[0x06];
  s16 lifetimeFrame;
  u8 pad08[0x0F - 0x08];
  u8 initialStateByte;
  u8 pad10[0x16 - 0x10];
  s16 lifetimeFrameLimit;
  u8 pad18[0x26 - 0x18];
  s16 sequenceId;
  u8 pad28[0x40 - 0x28];
  s16 sourceVecX;
  s16 sourceVecY;
  s16 sourceVecZ;
  u8 pad46[0x48 - 0x46];
  int sourcePosX;
  int sourcePosY;
  int sourcePosZ;
  int sourcePosW;
  int posX;
  int posY;
  int posZ;
  int startPosX;
  int startPosY;
  int startPosZ;
  float velocityX;
  float velocityY;
  float velocityZ;
  u32 behaviorFlags;
  u32 renderFlags;
  s16 scaleCounter;
  s16 scaleTarget;
  s16 scaleFrames;
  u8 encodedTableIndex;
  ExpgfxSlotStateBits stateBits;
  u8 colorByte0;
  u8 colorByte1;
  u8 colorByte2;
  u8 pad8F[0xA0 - 0x8F];
} ExpgfxSlot;

/*
 * These arrays are still linker-backed by recovered addresses, but the pool
 * roles are stable enough to use semantic aliases across the expgfx corridor.
 */
#define gExpgfxBoundsTemplates DAT_80310458
#define gExpgfxSpawnConfig DAT_8039caf8
#define gExpgfxInlineAttachedSource DAT_8039cb58
#define gProjgfxDefaultAttachedSource DAT_8039cff8
#define gExpgfxPoolSlotTypeIds gExpgfxSlotTypeIds
#define gExpgfxPoolFrameFlags DAT_80310528
#define gExpgfxPoolBounds DAT_8039b9b8
#define gExpgfxPoolSourceIds gExpgfxSlotSourceIds
#define gExpgfxPoolSourceModes DAT_8039c638
#define gExpgfxPoolBoundsTemplateIds DAT_8039c7d8
#define gExpgfxPoolActiveCounts gExpgfxSlotActiveCounts
#define gExpgfxPoolActiveMasks gExpgfxSlotActiveMasks

#endif /* MAIN_EXPGFX_INTERNAL_H_ */
