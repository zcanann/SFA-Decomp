#ifndef MAIN_OBJANIM_INTERNAL_H_
#define MAIN_OBJANIM_INTERNAL_H_

#include "ghidra_import.h"

typedef struct ObjHitReactState ObjHitReactState;

typedef struct ObjAnimHitReactRow {
  u8 pad00[0x16];
  s8 entryIndex;
  u8 pad17;
} ObjAnimHitReactRow;

#define OBJANIM_DEF_FLAG_CACHED_MOVES 0x40
#define OBJANIM_CACHED_MOVE_DATA_OFFSET 0x80
#define OBJANIM_FRAME_CMD_OFFSET 6
#define OBJANIM_FRAME_TYPE_MASK 0xF0
#define OBJANIM_FRAME_STEP_MASK 0x0F
#define OBJANIM_EVENT_COUNTDOWN_RESET 0x4000
#define OBJANIM_EVENT_FRAME_MASK 0x1FF
#define OBJANIM_EVENT_ID_SHIFT 9
#define OBJANIM_EVENT_ID_MASK 0x7F
#define OBJANIM_EVENT_ID_NONE 0x7F
#define OBJANIM_EVENT_TRIGGER_CAPACITY 8
#define OBJANIM_MOVE_GROUP_SHIFT 8
#define OBJANIM_MOVE_INDEX_MASK 0xFF

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
  s16 *hitReactMoveTable;
  u8 pad28[0x58 - 0x28];
  ObjAnimHitReactRow *hitReactTable;
  u8 pad5C[0x64 - 0x5C];
  u8 **moveData;
  u8 pad68[4];
  s16 *blendMoveIds;
  s16 moveBaseTable[0x3E];
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
  u8 *moveCache[2];
  u8 *blendMoveCache[2];
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

typedef struct ObjAnimBank {
  ObjAnimDef *animDef;
  u8 pad04[0x2C - 4];
  ObjAnimState *currentState;
  ObjAnimState *activeState;
} ObjAnimBank;

typedef struct ObjAnimComponent {
  u8 pad00[0x46];
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
  u8 resetFlag;
  u8 triggeredIds[8];
  u8 triggerCount;
} ObjAnimEventList;

static inline ObjAnimBank *ObjAnim_GetActiveBank(ObjAnimComponent *objAnim) {
  return objAnim->banks[objAnim->bankIndex];
}

static inline f64 ObjAnim_U32AsDouble(u32 value) {
  u64 bits = CONCAT44(0x43300000, value);
  return *(f64 *)&bits;
}

static inline s32 ObjAnim_ResolveMoveIndex(ObjAnimDef *animDef, u32 moveId) {
  s32 moveIndex =
      animDef->moveBaseTable[(s32)moveId >> OBJANIM_MOVE_GROUP_SHIFT] +
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

#endif /* MAIN_OBJANIM_INTERNAL_H_ */
