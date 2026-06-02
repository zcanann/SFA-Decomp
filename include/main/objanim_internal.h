#ifndef MAIN_OBJANIM_INTERNAL_H_
#define MAIN_OBJANIM_INTERNAL_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/objanim.h"

typedef struct ObjHitReactState ObjHitReactState;
typedef struct ObjHitReactMoveEntry ObjHitReactMoveEntry;

typedef struct ObjAnimHitReactRow {
  u8 pad00[0x16];
  s8 entryIndex;
  u8 pad17;
} ObjAnimHitReactRow;

#define OBJANIM_DEF_FLAG_CACHED_MOVES 0x40
/* Bits observed in ObjAnimState::flags during move advancement. */
#define OBJANIM_STATE_FLAG_HOLD_EVENT_COUNTDOWN 0x02
#define OBJANIM_STATE_FLAG_REFRESH_SAVED_STEP 0x08
#define OBJANIM_SET_MOVE_FLAG_SKIP_EVENT_COUNTDOWN 0x10
#define OBJANIM_MOVE_CACHE_SLOT_COUNT 2
#define OBJANIM_MISSING_MOVE_ID -1
#define OBJANIM_BLEND_MOVE_INDEX_INVALID -1
#define OBJANIM_CACHED_MOVE_DATA_OFFSET 0x80
#define OBJANIM_MOVE_ROOT_CURVE_OFFSET 4
#define OBJANIM_FRAME_CMD_OFFSET 6
#define OBJANIM_FRAME_TYPE_CLAMPED 0
#define OBJANIM_FRAME_TYPE_MASK 0xF0
#define OBJANIM_FRAME_STEP_MASK 0x0F
#define OBJANIM_EVENT_COUNTDOWN_RESET 0x4000
#define OBJANIM_EVENT_FRAME_MASK 0x1FF
#define OBJANIM_EVENT_ID_SHIFT 9
#define OBJANIM_EVENT_ID_MASK 0x7F
#define OBJANIM_EVENT_ID_NONE 0x7F
#define OBJANIM_EVENT_TRIGGER_CAPACITY 8
/* Event-scan flags: wrapped progress and reverse playback combine as a bitfield. */
#define OBJANIM_EVENT_SCAN_FORWARD 0
#define OBJANIM_EVENT_SCAN_WRAPPED 0x01
#define OBJANIM_EVENT_SCAN_REVERSE 0x02
#define OBJANIM_EVENT_SCAN_REVERSE_WRAPPED \
  (OBJANIM_EVENT_SCAN_WRAPPED | OBJANIM_EVENT_SCAN_REVERSE)
#define OBJANIM_MOVE_GROUP_SHIFT 8
#define OBJANIM_MOVE_INDEX_MASK 0xFF
#define OBJANIM_MOVE_GROUP_BASE_COUNT 0x3E
#define OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET 6
#define OBJANIM_ROOT_CURVE_Z_AXIS_OFFSET 10
#define OBJANIM_ROOT_CURVE_AXIS_COUNT 6
#define OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT 3
#define OBJANIM_ROOT_CURVE_AXIS_X 0
#define OBJANIM_ROOT_CURVE_AXIS_Y 1
#define OBJANIM_ROOT_CURVE_AXIS_Z 2
#define OBJANIM_ROOT_CURVE_AXIS_YAW 3
#define OBJANIM_ROOT_CURVE_AXIS_PITCH 4
#define OBJANIM_ROOT_CURVE_AXIS_ROLL 5
#define OBJANIM_DOUBLE_CONVERSION_HIGH_WORD 0x43300000
#define OBJANIM_S32_DOUBLE_BIAS_XOR 0x80000000
#define OBJANIM_U32_DOUBLE(value) ((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD, (value)))

/*
 * Shared state used by the object-animation helpers around main/objanim.c.
 * These names are still partially provisional, but the layouts are stable
 * enough to carry meaning across the nearby animation and hit-reaction code.
 */
typedef struct ObjAnimDef {
  u8 pad00[2];
  u16 flags;
  u16 modNo;
  u8 pad06[0x20 - 6];
  s16 *eventMoveTable;
  ObjHitReactMoveEntry *hitReactMoveTable;
  u8 pad28[0x58 - 0x28];
  ObjAnimHitReactRow *hitReactTable;
  u8 pad5C[0x64 - 0x5C];
  u8 **moveData;
  u8 pad68[4];
  s16 *cachedAnimIds;
  s16 moveGroupBaseIndices[OBJANIM_MOVE_GROUP_BASE_COUNT];
  u16 moveCount;
} ObjAnimDef;

typedef struct ObjAnimState {
  u8 pad00[4];
  f32 speed;
  f32 progress;
  f32 step;
  f32 savedStep;
  f32 segmentLength;
  f32 prevSegmentLength;
  u8 *moveCache[OBJANIM_MOVE_CACHE_SLOT_COUNT];
  u8 *blendMoveCache[OBJANIM_MOVE_CACHE_SLOT_COUNT];
  u8 pad2c[8];
  u8 *frameData;
  u8 *prevFrameData;
  u8 *frameCmd;
  u8 *prevFrameCmd;
  u16 moveCacheSlot;
  u16 prevMoveCacheSlot;
  u16 blendCacheSlot;
  u16 prevBlendCacheSlot;
  u8 pad4c[0x58 - 0x4C];
  u16 eventCountdown;
  u16 eventState;
  u16 prevEventState;
  u16 eventStep;
  s8 frameType;
  s8 prevFrameType;
  s8 blendToggle;
  s8 flags;
  s16 lastBlendMoveIndex;
} ObjAnimState;

typedef struct ObjAnimRootCurveAxis {
  s16 firstSample;
  s16 samples[1];
} ObjAnimRootCurveAxis;

/*
 * Root curves are packed by axis after the scale/sample-count header.  An axis
 * with firstSample == 0 occupies only that first s16; otherwise it is followed
 * by sampleCount additional s16 samples. Translation axes emit scaled floats,
 * while rotation axes emit raw s16 deltas into ObjAnimEventList.
 */
typedef struct ObjAnimRootCurve {
  f32 scale;
  s16 sampleCount;
  ObjAnimRootCurveAxis axes[1];
} ObjAnimRootCurve;

#define OBJMODEL_FLAG_SKIP_RESET_UPDATE 0x40

/*
 * Minimal recovered shape of the model pointer carried by ObjAnimComponent.
 * The named fields below are shared by root-motion sampling and hit-reaction
 * table loading; the rest of the object/model layout is still being mapped.
 */
typedef struct ObjModelInstance {
  u8 pad00[4];
  f32 rootMotionScaleBase;
  u8 pad08[0x10 - 0x08];
  s8 *jointData;
  u8 pad14[0x24 - 0x14];
  ObjHitReactMoveEntry *hitReactMoveTable;
  u8 pad28[0x44 - 0x28];
  u32 flags;
  u8 pad48[0x55 - 0x48];
  s8 modelCount;
  u8 pad56[0x5A - 0x56];
  u8 jointCount;
} ObjModelInstance;

typedef struct ObjAnimMoveData {
  u8 pad00;
  s8 frameInfo;
  u8 pad02[OBJANIM_MOVE_ROOT_CURVE_OFFSET - 2];
  s16 rootCurveOffset;
  u8 frameCmd[1];
} ObjAnimMoveData;

typedef struct ObjAnimBank {
  ObjAnimDef *animDef;
  u8 pad04[0x2C - 4];
  ObjAnimState *currentState;
  ObjAnimState *activeState;
} ObjAnimBank;

typedef struct ObjAnimComponent {
  u8 pad00[0x08];
  f32 rootMotionScale;
  u8 pad0C[0x46 - 0x0C];
  s16 objType;
  u8 pad48[0x50 - 0x48];
  ObjModelInstance *modelInstance;
  ObjHitReactState *hitReactState;
  u8 pad58[0x60 - 0x58];
  struct ObjAnimEventTable *eventTable;
  u8 pad64[0x6C - 0x64];
  u8 *jointPoseData;
  u8 pad70[0x7C - 0x70];
  ObjAnimBank **banks;
  u8 pad80[0x98 - 0x80];
  f32 currentMoveProgress;
  f32 activeMoveProgress;
  s16 currentMove;
  s16 activeMove;
  u8 padA4[0xAD - 0xA4];
  s8 bankIndex;
  s8 activeHitboxMode;
  s8 resetHitboxMode;
} ObjAnimComponent;

typedef struct ObjAnimEventTable {
  s32 byteCount;
  s16 *entries;
} ObjAnimEventTable;

typedef struct ObjAnimEventList {
  f32 rootDeltaX;
  f32 rootDeltaY;
  f32 rootDeltaZ;
  s16 rootYaw;
  s16 rootPitch;
  s16 rootRoll;
  u8 rootCurveValid;
  s8 triggeredIds[OBJANIM_EVENT_TRIGGER_CAPACITY];
  s8 triggerCount;
} ObjAnimEventList;

STATIC_ASSERT(sizeof(ObjAnimHitReactRow) == 0x18);
STATIC_ASSERT(offsetof(ObjAnimHitReactRow, entryIndex) == 0x16);

STATIC_ASSERT(sizeof(ObjAnimDef) == 0xF0);
STATIC_ASSERT(offsetof(ObjAnimDef, flags) == 0x02);
STATIC_ASSERT(offsetof(ObjAnimDef, modNo) == 0x04);
STATIC_ASSERT(offsetof(ObjAnimDef, eventMoveTable) == 0x20);
STATIC_ASSERT(offsetof(ObjAnimDef, hitReactMoveTable) == 0x24);
STATIC_ASSERT(offsetof(ObjAnimDef, hitReactTable) == 0x58);
STATIC_ASSERT(offsetof(ObjAnimDef, moveData) == 0x64);
STATIC_ASSERT(offsetof(ObjAnimDef, cachedAnimIds) == 0x6C);
STATIC_ASSERT(offsetof(ObjAnimDef, moveGroupBaseIndices) == 0x70);
STATIC_ASSERT(offsetof(ObjAnimDef, moveCount) == 0xEC);

STATIC_ASSERT(sizeof(ObjAnimState) == 0x68);
STATIC_ASSERT(offsetof(ObjAnimState, speed) == 0x04);
STATIC_ASSERT(offsetof(ObjAnimState, progress) == 0x08);
STATIC_ASSERT(offsetof(ObjAnimState, step) == 0x0C);
STATIC_ASSERT(offsetof(ObjAnimState, savedStep) == 0x10);
STATIC_ASSERT(offsetof(ObjAnimState, segmentLength) == 0x14);
STATIC_ASSERT(offsetof(ObjAnimState, prevSegmentLength) == 0x18);
STATIC_ASSERT(offsetof(ObjAnimState, moveCache) == 0x1C);
STATIC_ASSERT(offsetof(ObjAnimState, blendMoveCache) == 0x24);
STATIC_ASSERT(offsetof(ObjAnimState, frameData) == 0x34);
STATIC_ASSERT(offsetof(ObjAnimState, prevFrameData) == 0x38);
STATIC_ASSERT(offsetof(ObjAnimState, frameCmd) == 0x3C);
STATIC_ASSERT(offsetof(ObjAnimState, prevFrameCmd) == 0x40);
STATIC_ASSERT(offsetof(ObjAnimState, moveCacheSlot) == 0x44);
STATIC_ASSERT(offsetof(ObjAnimState, prevMoveCacheSlot) == 0x46);
STATIC_ASSERT(offsetof(ObjAnimState, blendCacheSlot) == 0x48);
STATIC_ASSERT(offsetof(ObjAnimState, prevBlendCacheSlot) == 0x4A);
STATIC_ASSERT(offsetof(ObjAnimState, eventCountdown) == 0x58);
STATIC_ASSERT(offsetof(ObjAnimState, eventState) == 0x5A);
STATIC_ASSERT(offsetof(ObjAnimState, prevEventState) == 0x5C);
STATIC_ASSERT(offsetof(ObjAnimState, eventStep) == 0x5E);
STATIC_ASSERT(offsetof(ObjAnimState, frameType) == 0x60);
STATIC_ASSERT(offsetof(ObjAnimState, prevFrameType) == 0x61);
STATIC_ASSERT(offsetof(ObjAnimState, blendToggle) == 0x62);
STATIC_ASSERT(offsetof(ObjAnimState, flags) == 0x63);
STATIC_ASSERT(offsetof(ObjAnimState, lastBlendMoveIndex) == 0x64);

STATIC_ASSERT(sizeof(ObjModelInstance) == 0x5C);
STATIC_ASSERT(offsetof(ObjModelInstance, rootMotionScaleBase) == 0x04);
STATIC_ASSERT(offsetof(ObjModelInstance, jointData) == 0x10);
STATIC_ASSERT(offsetof(ObjModelInstance, hitReactMoveTable) == 0x24);
STATIC_ASSERT(offsetof(ObjModelInstance, flags) == 0x44);
STATIC_ASSERT(offsetof(ObjModelInstance, modelCount) == 0x55);
STATIC_ASSERT(offsetof(ObjModelInstance, jointCount) == 0x5A);

STATIC_ASSERT(sizeof(ObjAnimMoveData) == 0x08);
STATIC_ASSERT(offsetof(ObjAnimMoveData, frameInfo) == 0x01);
STATIC_ASSERT(offsetof(ObjAnimMoveData, rootCurveOffset) == 0x04);
STATIC_ASSERT(offsetof(ObjAnimMoveData, frameCmd) == OBJANIM_FRAME_CMD_OFFSET);

STATIC_ASSERT(sizeof(ObjAnimBank) == 0x34);
STATIC_ASSERT(offsetof(ObjAnimBank, animDef) == 0x00);
STATIC_ASSERT(offsetof(ObjAnimBank, currentState) == 0x2C);
STATIC_ASSERT(offsetof(ObjAnimBank, activeState) == 0x30);

STATIC_ASSERT(sizeof(ObjAnimComponent) == 0xB0);
STATIC_ASSERT(offsetof(ObjAnimComponent, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ObjAnimComponent, objType) == 0x46);
STATIC_ASSERT(offsetof(ObjAnimComponent, modelInstance) == 0x50);
STATIC_ASSERT(offsetof(ObjAnimComponent, hitReactState) == 0x54);
STATIC_ASSERT(offsetof(ObjAnimComponent, eventTable) == 0x60);
STATIC_ASSERT(offsetof(ObjAnimComponent, jointPoseData) == 0x6C);
STATIC_ASSERT(offsetof(ObjAnimComponent, banks) == 0x7C);
STATIC_ASSERT(offsetof(ObjAnimComponent, currentMoveProgress) == 0x98);
STATIC_ASSERT(offsetof(ObjAnimComponent, activeMoveProgress) == 0x9C);
STATIC_ASSERT(offsetof(ObjAnimComponent, currentMove) == 0xA0);
STATIC_ASSERT(offsetof(ObjAnimComponent, activeMove) == 0xA2);
STATIC_ASSERT(offsetof(ObjAnimComponent, bankIndex) == 0xAD);
STATIC_ASSERT(offsetof(ObjAnimComponent, activeHitboxMode) == 0xAE);
STATIC_ASSERT(offsetof(ObjAnimComponent, resetHitboxMode) == 0xAF);

STATIC_ASSERT(sizeof(ObjAnimEventTable) == 0x08);
STATIC_ASSERT(offsetof(ObjAnimEventTable, byteCount) == 0x00);
STATIC_ASSERT(offsetof(ObjAnimEventTable, entries) == 0x04);

STATIC_ASSERT(sizeof(ObjAnimEventList) == 0x1C);
STATIC_ASSERT(offsetof(ObjAnimEventList, rootDeltaX) == 0x00);
STATIC_ASSERT(offsetof(ObjAnimEventList, rootYaw) == 0x0C);
STATIC_ASSERT(offsetof(ObjAnimEventList, rootCurveValid) == 0x12);
STATIC_ASSERT(offsetof(ObjAnimEventList, triggeredIds) == 0x13);
STATIC_ASSERT(offsetof(ObjAnimEventList, triggerCount) == 0x1B);

static inline ObjAnimBank *ObjAnim_GetActiveBank(ObjAnimComponent *objAnim) {
  return objAnim->banks[objAnim->bankIndex];
}

static inline f64 ObjAnim_U32AsDouble(u32 value) {
  u64 bits = CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD, value);
  return *(f64 *)&bits;
}

static inline f64 ObjAnim_S32AsDouble(s32 value) {
  return ObjAnim_U32AsDouble((u32)(value ^ (s32)OBJANIM_S32_DOUBLE_BIAS_XOR));
}

static inline s32 ObjAnim_ResolveMoveIndex(ObjAnimDef *animDef, u32 moveId) {
  s32 moveIndex =
      animDef->moveGroupBaseIndices[(s32)moveId >> OBJANIM_MOVE_GROUP_SHIFT] +
      (moveId & OBJANIM_MOVE_INDEX_MASK);

  if (moveIndex >= animDef->moveCount) {
    moveIndex = animDef->moveCount - 1;
  }
  if (moveIndex < 0) {
    moveIndex = 0;
  }
  return moveIndex;
}

static inline ObjAnimDef *ObjAnim_GetAnimDef(ObjAnimComponent *objAnim) {
  return ObjAnim_GetActiveBank(objAnim)->animDef;
}

static inline ObjAnimState *ObjAnim_GetActiveState(ObjAnimComponent *objAnim) {
  return ObjAnim_GetActiveBank(objAnim)->activeState;
}

static inline ObjAnimState *ObjAnim_GetCurrentState(ObjAnimComponent *objAnim) {
  return ObjAnim_GetActiveBank(objAnim)->currentState;
}

static inline s32 ObjAnim_GetHitReactEntryIndex(ObjAnimDef *animDef, s32 sphereIndex) {
  return animDef->hitReactTable[sphereIndex].entryIndex;
}

static inline ObjAnimMoveData *ObjAnim_GetMoveData(ObjAnimDef *animDef, ObjAnimState *state,
                                                   u16 slot) {
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    return (ObjAnimMoveData *)(state->moveCache[slot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  return (ObjAnimMoveData *)animDef->moveData[slot];
}

static inline ObjAnimMoveData *ObjAnim_GetBlendMoveData(ObjAnimDef *animDef, ObjAnimState *state,
                                                        u16 slot) {
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    return (ObjAnimMoveData *)(state->blendMoveCache[slot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  return (ObjAnimMoveData *)animDef->moveData[slot];
}

#endif /* MAIN_OBJANIM_INTERNAL_H_ */
