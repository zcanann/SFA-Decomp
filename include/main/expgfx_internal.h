#ifndef MAIN_EXPGFX_INTERNAL_H_
#define MAIN_EXPGFX_INTERNAL_H_

#include "global.h"
#include "ghidra_import.h"

#define EXPGFX_POOL_COUNT 0x50
#define EXPGFX_POOL_RESET_BATCH_SIZE 8
#define EXPGFX_POOL_GROUP_COUNT (EXPGFX_POOL_COUNT / EXPGFX_POOL_RESET_BATCH_SIZE)
#define EXPGFX_POOL_SEARCH_BATCH_SIZE 5
#define EXPGFX_POOL_SEARCH_BATCH_COUNT (EXPGFX_POOL_COUNT / EXPGFX_POOL_SEARCH_BATCH_SIZE)
#define EXPGFX_SLOTS_PER_POOL 0x19
#define EXPGFX_SLOT_SIZE 0xA0
#define EXPGFX_POOL_BYTES (EXPGFX_SLOTS_PER_POOL * EXPGFX_SLOT_SIZE)
#define EXPGFX_POOL_CACHE_LINE_COUNT 0x7e
#define EXPGFX_POOL_ALLOC_HEAP 0x14
#define EXPGFX_SPAWN_CONFIG_PREFIX_BYTES 0x60
#define EXPGFX_RESOURCE_TABLE_COUNT 0x20
#define EXPGFX_RESOURCE_EVICTION_RESET 1000
#define EXPGFX_RESOURCE_EVICTION_SCAN_INITIAL 0xFA00
#define EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT 0x4000
#define EXPGFX_RESOURCE_ACQUIRE_TEXTURE_BUSY -1
#define EXPGFX_RESOURCE_ACQUIRE_LOAD_FAILED -2
#define EXPGFX_RESOURCE_ACQUIRE_RELOAD_FAILED -3
#define EXPGFX_RESOURCE_ACQUIRE_LOADING_UNLOCKED -4
#define EXPGFX_EXPTAB_ENTRY_COUNT EXPGFX_POOL_COUNT
#define EXPGFX_INVALID_TABLE_INDEX -1
#define EXPGFX_INVALID_POOL_INDEX -1
#define EXPGFX_INVALID_SLOT_TYPE -1
#define EXPGFX_INVALID_SEQUENCE_ID -1
#define EXPGFX_REFCOUNT_OVERFLOW 0xFFFF
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
#define EXPGFX_STATIC_MISMATCH_ADD_REMOVE_STRING_OFFSET 0x358
#define EXPGFX_STATIC_NO_TEXTURE_STRING_OFFSET 0x384

/*
 * Flag names describe observed behavior in expgfx_addremove and drawGlow. Keep
 * them local until neighboring constructors and asset tables prove the
 * original terms.
 */
#define EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_A 0x00000002
#define EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B 0x00000004
#define EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY 0x00000008
#define EXPGFX_BEHAVIOR_DEPTH_MODE_OVERRIDE 0x00000010
#define EXPGFX_BEHAVIOR_ALPHA_PULSE 0x00000100
#define EXPGFX_BEHAVIOR_ALPHA_FADE_OUT 0x00000200
#define EXPGFX_BEHAVIOR_FLIP_TEX_T 0x00000040
#define EXPGFX_BEHAVIOR_FLIP_TEX_S 0x00000080
#define EXPGFX_BEHAVIOR_IMPACT_BOOST_LATCH 0x00000400
#define EXPGFX_BEHAVIOR_HOLD_LIFETIME_TIMER 0x00000800
#define EXPGFX_BEHAVIOR_GROUND_PARTFX_ON_IMPACT 0x00000020
#define EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1 0x00001000
#define EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2 0x00002000
#define EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3 0x00004000
#define EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_4 0x00008000
#define EXPGFX_BEHAVIOR_GROUND_IMPACT_MASK \
  (EXPGFX_BEHAVIOR_GROUND_PARTFX_ON_IMPACT | EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_1 | \
   EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_2 | EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_3 | \
   EXPGFX_BEHAVIOR_GROUND_IMPACT_STAGE_4)
#define EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A 0x00020000
#define EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE 0x00040000
#define EXPGFX_BEHAVIOR_BILLBOARD_USE_PITCH 0x00080000
#define EXPGFX_BEHAVIOR_SCALE_FROM_ZERO 0x00100000
#define EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER 0x00000001
#define EXPGFX_BEHAVIOR_COPY_ATTACHED_SOURCE 0x00200000
#define EXPGFX_BEHAVIOR_RANDOMIZE_SCALE 0x00400000
#define EXPGFX_BEHAVIOR_ALPHA_FADE_TO_OPAQUE 0x00800000
#define EXPGFX_BEHAVIOR_BILLBOARD_LOCK_A 0x02000000
#define EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B 0x04000000
#define EXPGFX_BEHAVIOR_FAST_Y_RESPONSE 0x01000000
#define EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_B 0x04000000
#define EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A 0x08000000
#define EXPGFX_BEHAVIOR_IMPACT_POSITION_LOCKED 0x08000000
#define EXPGFX_BEHAVIOR_WATER_RIPPLE_ON_IMPACT 0x10000000
#define EXPGFX_BEHAVIOR_SOURCE_MODE_FLAG 0x20000000
#define EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY 0x40000000
#define EXPGFX_BEHAVIOR_RANDOM_XZ_JITTER 0x80000000

#define EXPGFX_RENDER_DEPTH_BLEND_MODE 0x00000001
#define EXPGFX_RENDER_INIT_QUAD 0x00000002
#define EXPGFX_RENDER_BACKDATE_MOTION 0x00000008
#define EXPGFX_RENDER_AIM_AT_ACTOR 0x00000010
#define EXPGFX_RENDER_OVERRIDE_COLORS 0x00000020
#define EXPGFX_RENDER_ALPHA_TEXTURE_SETUP 0x00000040
#define EXPGFX_RENDER_MODULATE_ALPHA_SOURCE 0x00000080
#define EXPGFX_RENDER_QUAD_SCALE_Y8 0x00000100
#define EXPGFX_RENDER_QUAD_SCALE_X32 0x00000200
#define EXPGFX_RENDER_QUAD_SWAP_XZ_SCALE_Z32 0x00000400
#define EXPGFX_RENDER_AIM_AT_SOURCE_OBJECT 0x00000400
#define EXPGFX_RENDER_BLEND_ADDITIVE 0x00000800
#define EXPGFX_RENDER_SCALE_OVER_LIFETIME 0x00002000
#define EXPGFX_RENDER_VELOCITY_BOOST_A 0x00010000
#define EXPGFX_RENDER_ALT_ALPHA_SETUP 0x00010000
#define EXPGFX_RENDER_VELOCITY_BOOST_B 0x00020000
#define EXPGFX_RENDER_VELOCITY_BOOST_C 0x00040000
#define EXPGFX_RENDER_VELOCITY_DAMP 0x00080000
#define EXPGFX_RENDER_RANDOM_VELOCITY_BURST 0x00100000
#define EXPGFX_RENDER_STRETCHED_TRAIL 0x00200000
#define EXPGFX_RENDER_ALPHA_FADE_IN 0x00400000
#define EXPGFX_RENDER_AMBIENT_COLOR_SCALED 0x00800000
#define EXPGFX_RENDER_AMBIENT_COLOR_DIRECT 0x01000000
#define EXPGFX_RENDER_PHASE_ROTATE_A 0x04000000
#define EXPGFX_RENDER_PHASE_ROTATE_B 0x08000000
#define EXPGFX_RENDER_ATTRACT_TO_PLAYER 0x10000000
#define EXPGFX_RENDER_ATTRACT_TO_TRICKY 0x20000000
#define EXPGFX_RENDER_ATTRACT_TARGET_MASK \
  (EXPGFX_RENDER_ATTRACT_TO_PLAYER | EXPGFX_RENDER_ATTRACT_TO_TRICKY)
#define EXPGFX_RENDER_IMPACT_POSITION_LOCKED 0x40000000

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
#define EXPGFX_STATIC_BOUNDS_TEMPLATE_COUNT \
  (EXPGFX_STATIC_POOL_SLOT_TYPE_IDS_OFFSET / sizeof(ExpgfxBounds))

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
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  u8 pad06[0x0C - 0x06];
  f32 localPosX;
  f32 localPosY;
  f32 localPosZ;
  f32 worldPosX;
  f32 worldPosY;
  f32 worldPosZ;
  f32 velocityX;
  f32 velocityY;
  f32 velocityZ;
  u8 pad30[0x36 - 0x30];
  u8 alpha;
  u8 pad37[0x46 - 0x37];
  /* Type 0xD4 updates frame flags for every tracked pool, not just pointer matches. */
  s16 objType;
} ExpgfxSourceObject;

STATIC_ASSERT(offsetof(ExpgfxSourceObject, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExpgfxSourceObject, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExpgfxSourceObject, velocityX) == 0x24);
STATIC_ASSERT(offsetof(ExpgfxSourceObject, alpha) == 0x36);
STATIC_ASSERT(offsetof(ExpgfxSourceObject, objType) == 0x46);

typedef struct ExpgfxPoolSourcePosition {
  u8 pad00[0x0C];
  f32 x;
  f32 y;
  f32 z;
} ExpgfxPoolSourcePosition;

typedef struct ExpgfxTrackedSourceFrameMask {
  u32 highWord;
  u32 lowWord;
} ExpgfxTrackedSourceFrameMask;

typedef union ExpgfxFloatWord {
  int bits;
  f32 value;
} ExpgfxFloatWord;

STATIC_ASSERT(sizeof(ExpgfxFloatWord) == 4);

/*
 * Retail warning strings call this structure "exptab". The key fields are
 * still only partially understood, but the table's role and lifetime rules
 * are stable enough to stop treating it as raw integer arrays.
 */
typedef struct ExpgfxTableEntry {
  /* The add/remove paths key entries by source identity plus an optional attached-source key. */
  u32 sourceId;
  u32 attachedTableKey;
  u32 resource;
  u16 refCount;
  s16 resourceId;
} ExpgfxTableEntry;

STATIC_ASSERT(sizeof(ExpgfxTableEntry) == EXPGFX_TABLE_ENTRY_SIZE);
STATIC_ASSERT(offsetof(ExpgfxTableEntry, sourceId) == 0x00);
STATIC_ASSERT(offsetof(ExpgfxTableEntry, attachedTableKey) == 0x04);
STATIC_ASSERT(offsetof(ExpgfxTableEntry, resource) == 0x08);
STATIC_ASSERT(offsetof(ExpgfxTableEntry, refCount) == 0x0C);
STATIC_ASSERT(offsetof(ExpgfxTableEntry, resourceId) == 0x0E);

#define EXPGFX_EXPTAB_BYTES (EXPGFX_EXPTAB_ENTRY_COUNT * sizeof(ExpgfxTableEntry))

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
  ExpgfxFloatWord sourcePosX;
  ExpgfxFloatWord sourcePosY;
  ExpgfxFloatWord sourcePosZ;
  ExpgfxFloatWord sourcePosW;
  float velocityX;
  float velocityY;
  float velocityZ;
  int attachedTableKey;
} ExpgfxAttachedSourceState;

typedef union ExpgfxSpawnTextureWord {
  u32 word;
  struct {
    u16 setupFlags;
    s16 textureId;
  } parts;
} ExpgfxSpawnTextureWord;

typedef struct ExpgfxSpawnColorPair {
  u8 value;
  u8 lowByte;
} ExpgfxSpawnColorPair;

/*
 * Spawn requests are sourced from the current expgfx context. Not every word
 * is understood yet, but the stable fields are worth naming directly.
 */
typedef struct ExpgfxSpawnConfig {
  void *attachedSource;
  s32 quadVertex3Pad06;
  s32 lifetimeFrames;
  union {
    struct {
      s16 sourceVecX;
      s16 sourceVecY;
      s16 sourceVecZ;
      u8 pad12[0x14 - 0x12];
      ExpgfxFloatWord sourcePosX;
      ExpgfxFloatWord sourcePosY;
      ExpgfxFloatWord sourcePosZ;
      ExpgfxFloatWord sourcePosW;
    };
    struct {
      f32 localOffsetX;
      f32 localOffsetY;
      f32 localOffsetZ;
      u8 padLocalOffset18[0x24 - 0x18];
    } actorAimOffset;
  };
  float velocityX;
  float velocityY;
  float velocityZ;
  ExpgfxFloatWord startPosX;
  ExpgfxFloatWord startPosY;
  ExpgfxFloatWord startPosZ;
  float scale;
  ExpgfxSpawnTextureWord texture;
  u32 behaviorFlags;
  u32 renderFlags;
  u32 overrideColor0;
  u32 overrideColor1;
  u32 overrideColor2;
  ExpgfxSpawnColorPair colorByte0;
  ExpgfxSpawnColorPair colorByte1;
  ExpgfxSpawnColorPair colorByte2;
  u8 pad5E[0x60 - 0x5E];
  u8 initialAlpha;
  u8 linkGroup;
} ExpgfxSpawnConfig;

STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, attachedSource) == 0x00);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, quadVertex3Pad06) == 0x04);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, sourceVecX) == 0x0C);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, actorAimOffset.localOffsetX) == 0x0C);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, actorAimOffset.localOffsetY) == 0x10);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, actorAimOffset.localOffsetZ) == 0x14);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, sourcePosW) == 0x20);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, velocityX) == 0x24);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, startPosX) == 0x30);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, scale) == 0x3C);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, texture) == 0x40);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, texture.parts.textureId) == 0x42);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, behaviorFlags) == 0x44);
STATIC_ASSERT(offsetof(ExpgfxSpawnConfig, colorByte0) == 0x58);
STATIC_ASSERT(sizeof(ExpgfxSpawnConfig) == 0x64);

typedef struct ExpgfxResourceEntry {
  void *resource;
  s32 evictionScore;
  s32 resourceId;
  u32 reserved;
} ExpgfxResourceEntry;

STATIC_ASSERT(offsetof(ExpgfxResourceEntry, resource) == 0x00);
STATIC_ASSERT(offsetof(ExpgfxResourceEntry, evictionScore) == 0x04);
STATIC_ASSERT(offsetof(ExpgfxResourceEntry, resourceId) == 0x08);
STATIC_ASSERT(offsetof(ExpgfxResourceEntry, reserved) == 0x0C);
STATIC_ASSERT(sizeof(ExpgfxResourceEntry) == 0x10);

typedef struct ExpgfxResourceHandle {
  u8 pad00[0x0E];
  u16 refCount;
  u8 pad10[0x14 - 0x10];
  u16 linkGroup;
} ExpgfxResourceHandle;

STATIC_ASSERT(offsetof(ExpgfxResourceHandle, refCount) == 0x0E);
STATIC_ASSERT(offsetof(ExpgfxResourceHandle, linkGroup) == 0x14);

typedef struct ExpgfxQuadTemplateVertex {
  s16 x;
  s16 y;
  s16 z;
} ExpgfxQuadTemplateVertex;

/*
 * Recovered shape of the static expgfx data blob. The warning strings and
 * quad templates sit in the same source corridor as the exptab diagnostics,
 * so keeping the layout together makes future offset-to-field promotion
 * less error-prone.
 */
typedef struct ExpgfxStaticDataLayout {
  ExpgfxBounds boundsTemplates[EXPGFX_STATIC_BOUNDS_TEMPLATE_COUNT];
  s16 poolSlotTypeIds[EXPGFX_POOL_COUNT];
  u8 poolFrameFlags[EXPGFX_POOL_COUNT];
  u8 pad120[EXPGFX_STATIC_QUAD_TEMPLATE_A_OFFSET -
            (EXPGFX_STATIC_POOL_FRAME_FLAGS_OFFSET + EXPGFX_POOL_COUNT)];
  ExpgfxQuadTemplateVertex quadTemplateA[4];
  ExpgfxQuadTemplateVertex quadTemplateB[4];
  u8 pad180[EXPGFX_STATIC_MISMATCH_ADD_REMOVE_STRING_OFFSET -
            (EXPGFX_STATIC_QUAD_TEMPLATE_B_OFFSET + sizeof(ExpgfxQuadTemplateVertex) * 4)];
  char mismatchInAddRemoveString[EXPGFX_STATIC_NO_TEXTURE_STRING_OFFSET -
                                 EXPGFX_STATIC_MISMATCH_ADD_REMOVE_STRING_OFFSET];
  char noTextureString[1];
} ExpgfxStaticDataLayout;

STATIC_ASSERT(offsetof(ExpgfxStaticDataLayout, poolSlotTypeIds) == EXPGFX_STATIC_POOL_SLOT_TYPE_IDS_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxStaticDataLayout, poolFrameFlags) == EXPGFX_STATIC_POOL_FRAME_FLAGS_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxStaticDataLayout, quadTemplateA) == EXPGFX_STATIC_QUAD_TEMPLATE_A_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxStaticDataLayout, quadTemplateB) == EXPGFX_STATIC_QUAD_TEMPLATE_B_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxStaticDataLayout, mismatchInAddRemoveString) == EXPGFX_STATIC_MISMATCH_ADD_REMOVE_STRING_OFFSET);

/*
 * Retail diagnostics call the 0x980 table "exptab". This layout captures the
 * surrounding runtime pool state that expgfxRemove, expgfxGetSlot, and
 * expgfx_addremove currently access through offsets.
 */
typedef struct ExpgfxRuntimeDataLayout {
  ExpgfxResourceEntry resourceTable[EXPGFX_RESOURCE_TABLE_COUNT];
  ExpgfxBounds poolBounds[EXPGFX_POOL_COUNT];
  ExpgfxTableEntry expTab[EXPGFX_EXPTAB_ENTRY_COUNT];
  u8 poolSourceModes[EXPGFX_POOL_COUNT];
  u32 poolSourceIds[EXPGFX_POOL_COUNT];
  ExpgfxTrackedSourceFrameMask trackedSourceFrameMasks[2];
  u8 poolBoundsTemplateIds[EXPGFX_POOL_COUNT];
  s8 poolActiveCounts[EXPGFX_POOL_COUNT];
  u32 poolActiveMasks[EXPGFX_POOL_COUNT];
  u32 slotPoolBases[EXPGFX_POOL_COUNT];
} ExpgfxRuntimeDataLayout;

STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, resourceTable) == EXPGFX_RESOURCE_TABLE_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, poolBounds) == EXPGFX_POOL_BOUNDS_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, expTab) == EXPGFX_EXPTAB_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, poolSourceModes) == EXPGFX_POOL_SOURCE_MODES_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, poolSourceIds) == EXPGFX_POOL_SOURCE_IDS_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, trackedSourceFrameMasks) == EXPGFX_TRACKED_SOURCE_FRAME_MASKS_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, poolBoundsTemplateIds) == EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, poolActiveCounts) == EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, poolActiveMasks) == EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
STATIC_ASSERT(offsetof(ExpgfxRuntimeDataLayout, slotPoolBases) == EXPGFX_SLOT_POOL_BASES_OFFSET);
STATIC_ASSERT(sizeof(ExpgfxRuntimeDataLayout) == 0x1340);

typedef union ExpgfxSlotStateBits {
  u8 value;
  struct {
    u8 padHi : 4;
    u8 initPhase : 2;
    u8 quadReady : 1;
    u8 frameParity : 1;
  } bits;
} ExpgfxSlotStateBits;

/*
 * The first 0x40 bytes of each slot double as the cached quad stream rendered
 * by drawGlow. Several lifetime fields below intentionally alias otherwise
 * unused or alpha bytes in this stream.
 */
typedef struct ExpgfxQuadVertex {
  s16 x;
  s16 y;
  s16 z;
  s16 pad06;
  s16 texS;
  s16 texT;
  u8 colorR;
  u8 colorG;
  u8 colorB;
  u8 alpha;
} ExpgfxQuadVertex;

typedef struct ExpgfxSlot {
  u8 pad00[0x06];
  s16 lifetimeFrame;
  u8 pad08[0x0F - 0x08];
  u8 initialAlpha;
  u8 pad10[0x16 - 0x10];
  s16 lifetimeFrameLimit;
  u8 pad18[0x26 - 0x18];
  s16 sequenceId;
  u8 pad28[0x36 - 0x28];
  s16 soundHandle;
  u8 pad38[0x40 - 0x38];
  s16 sourceVecX;
  s16 sourceVecY;
  s16 sourceVecZ;
  u8 pad46[0x48 - 0x46];
  ExpgfxFloatWord sourcePosX;
  ExpgfxFloatWord sourcePosY;
  ExpgfxFloatWord sourcePosZ;
  ExpgfxFloatWord sourcePosW;
  ExpgfxFloatWord posX;
  ExpgfxFloatWord posY;
  ExpgfxFloatWord posZ;
  ExpgfxFloatWord startPosX;
  ExpgfxFloatWord startPosY;
  ExpgfxFloatWord startPosZ;
  float velocityX;
  float velocityY;
  float velocityZ;
  u32 behaviorFlags;
  u32 renderFlags;
  u16 scaleCurrent;
  u16 scaleTarget;
  u16 scaleStep;
  u8 encodedTableIndex;
  ExpgfxSlotStateBits stateBits;
  u8 colorByte0;
  u8 colorByte1;
  u8 colorByte2;
  u8 pad8F[0x90 - 0x8F];
  f32 renderX;
  f32 renderY;
  f32 renderZ;
  u8 pad9C[0xA0 - 0x9C];
} ExpgfxSlot;

STATIC_ASSERT(sizeof(ExpgfxSlot) == EXPGFX_SLOT_SIZE);
STATIC_ASSERT(offsetof(ExpgfxSlot, lifetimeFrame) == 0x06);
STATIC_ASSERT(offsetof(ExpgfxSlot, initialAlpha) == 0x0F);
STATIC_ASSERT(offsetof(ExpgfxSlot, lifetimeFrameLimit) == 0x16);
STATIC_ASSERT(offsetof(ExpgfxSlot, sequenceId) == 0x26);
STATIC_ASSERT(offsetof(ExpgfxSlot, soundHandle) == 0x36);
STATIC_ASSERT(offsetof(ExpgfxSlot, sourceVecX) == 0x40);
STATIC_ASSERT(offsetof(ExpgfxSlot, sourcePosX) == 0x48);
STATIC_ASSERT(offsetof(ExpgfxSlot, posX) == 0x58);
STATIC_ASSERT(offsetof(ExpgfxSlot, startPosX) == 0x64);
STATIC_ASSERT(offsetof(ExpgfxSlot, velocityX) == 0x70);
STATIC_ASSERT(offsetof(ExpgfxSlot, behaviorFlags) == 0x7C);
STATIC_ASSERT(offsetof(ExpgfxSlot, renderFlags) == 0x80);
STATIC_ASSERT(offsetof(ExpgfxSlot, scaleCurrent) == 0x84);
STATIC_ASSERT(offsetof(ExpgfxSlot, scaleTarget) == 0x86);
STATIC_ASSERT(offsetof(ExpgfxSlot, scaleStep) == 0x88);
STATIC_ASSERT(offsetof(ExpgfxSlot, encodedTableIndex) == 0x8A);
STATIC_ASSERT(offsetof(ExpgfxSlot, stateBits) == 0x8B);
STATIC_ASSERT(offsetof(ExpgfxSlot, colorByte0) == 0x8C);
STATIC_ASSERT(offsetof(ExpgfxSlot, renderX) == 0x90);

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
#define EXPGFX_STATIC_DATA ((ExpgfxStaticDataLayout *)gExpgfxStaticData)
#define EXPGFX_RUNTIME_DATA ((ExpgfxRuntimeDataLayout *)gExpgfxRuntimeData)

extern u8 gExpgfxStaticData[];
extern u8 gExpgfxRuntimeData[];
extern ExpgfxTableEntry gExpgfxTableEntries[];
extern u32 gExpgfxTrackedPoolSourceIds[];
extern ExpgfxTrackedSourceFrameMask gExpgfxTrackedSourceFrameMasks[];
extern s16 gExpgfxStaticPoolSlotTypeIds[];
extern u8 gExpgfxStaticPoolFrameFlags[];
extern u32 gExpgfxSlotActiveMasks[];
extern u32 gExpgfxSlotPoolBases[];
extern int gExpgfxTextureFreeInProgress;
extern volatile s16 gExpgfxSequenceCounter;
extern volatile u8 gExpgfxFrameParityBit;
extern u8 gExpgfxUpdatingActivePools;
extern u8 gExpgfxRenderResetPending;
extern int gExpgfxLastAddedSlot;
extern char sExpgfxAddToTableUsageOverflow[];
extern char sExpgfxExpTabIsFull[];
extern char sExpgfxInvalidTabIndex[];
extern char sExpgfxMismatchInAddRemove[];
extern char sExpgfxScaleOverflow[];
extern char sExpgfxNoTexture[];

#endif /* MAIN_EXPGFX_INTERNAL_H_ */
