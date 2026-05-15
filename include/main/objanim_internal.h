#ifndef MAIN_OBJANIM_INTERNAL_H_
#define MAIN_OBJANIM_INTERNAL_H_

#include "ghidra_import.h"

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
  s16 eventStep;
  s8 frameType;
  s8 prevFrameType;
  s8 blendToggle;
  s8 flags;
  s16 lastBlendMoveIndex;
} ObjAnimState;

typedef struct ObjAnimRootCurve {
  f32 scale;
  s16 sampleCount;
  s16 axisData[1];
} ObjAnimRootCurve;

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
  void *modelInstance;
  ObjHitReactState *hitReactState;
  u8 pad58[0x60 - 0x58];
  struct ObjAnimEventTable *eventTable;
  u8 pad64[0x7C - 0x64];
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
  u8 triggeredIds[OBJANIM_EVENT_TRIGGER_CAPACITY];
  u8 triggerCount;
} ObjAnimEventList;

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
