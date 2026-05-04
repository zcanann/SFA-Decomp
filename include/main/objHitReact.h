#ifndef MAIN_OBJHITREACT_H_
#define MAIN_OBJHITREACT_H_

#include "ghidra_import.h"

typedef struct ObjHitReactEntry ObjHitReactEntry;

typedef struct ObjHitReactMoveEntry {
  s16 moveId;
  s16 firstEntryIndex;
  s16 entryCount;
} ObjHitReactMoveEntry;

#define OBJHITREACT_MAX_RESET_OBJECTS 0x32
#define OBJHITREACT_STATE_ACTIVE 0x01
#define OBJHITREACT_STATE_RESET_PENDING 0x08
#define OBJHITREACT_COLLISION_SKIP_REACTION 0x11
#define OBJHITREACT_HIT_FX_MODE_EFFECT 1
#define OBJHITREACT_HIT_EFFECT_ID 0x5A
#define OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS 0x401
#define OBJHITREACT_RESET_FRAME_COUNT 0x400

typedef struct ObjHitReactState {
  int activeHit;
  s16 activeEntryCount;
  s16 entryCapacity;
  ObjHitReactEntry *entries;
  u8 pad0C[0x58 - 0x0C];
  s16 resetFrameCount;
  u8 pad5A[0x60 - 0x5A];
  s16 flags;
  u8 resetFlags;
} ObjHitReactState;

struct ObjHitReactEntry {
  s16 hitSfxA;
  s16 hitSfxB;
  s16 reactionAnim;
  u8 pad06[2];
  u8 hitFxMode;
  u8 pad09[3];
  f32 cooldown;
  u8 pad10[4];
};

int objHitReact_update(int obj,ObjHitReactEntry *entries,u32 entryCount,u32 reactionState,float *cooldown);
void ObjHitReact_ResetActiveObjects(int objectCount);

#define objHitReactFn_80089890 objHitReact_update

#endif /* MAIN_OBJHITREACT_H_ */
