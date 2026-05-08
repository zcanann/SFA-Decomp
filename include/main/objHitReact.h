#ifndef MAIN_OBJHITREACT_H_
#define MAIN_OBJHITREACT_H_

#include "ghidra_import.h"

typedef struct ObjHitReactEntry ObjHitReactEntry;
typedef struct ObjAnimComponent ObjAnimComponent;

typedef struct ObjHitReactEffectOrigin {
  undefined4 m[4];
} ObjHitReactEffectOrigin;

typedef struct ObjHitReactEffectPos {
  s16 x;
  s16 y;
  s16 z;
  u8 pad06[2];
  f32 scale;
} ObjHitReactEffectPos;

typedef struct ObjHitReactEffectColorArgs {
  u32 hitFxMode;
  u32 colorR;
  u32 colorG;
  u32 colorB;
} ObjHitReactEffectColorArgs;

typedef void (*ObjHitReactEffectSpawnFn)(int parent,int mode,ObjHitReactEffectPos *pos,
                                         u32 flags,int sequenceId,void *args);

typedef struct ObjHitReactEffectVTable {
  void *pad00;
  ObjHitReactEffectSpawnFn spawn;
} ObjHitReactEffectVTable;

typedef struct ObjHitReactEffectHandle {
  ObjHitReactEffectVTable *vtable;
} ObjHitReactEffectHandle;

typedef struct ObjHitReactMoveEntry {
  s16 moveId;
  s16 firstEntryIndex;
  s16 entryCount;
} ObjHitReactMoveEntry;

#define OBJHITREACT_MAX_RESET_OBJECTS 0x32
#define OBJHITREACT_STATE_ACTIVE 0x01
#define OBJHITREACT_STATE_RESET_PENDING 0x08
#define OBJHITREACT_REACTION_STATE_MASK 0xff
#define OBJHITREACT_REACTION_STATE_INACTIVE 0
#define OBJHITREACT_REACTION_STATE_ACTIVE 1
#define OBJHITREACT_COLLISION_SKIP_REACTION 0x11
#define OBJHITREACT_NO_SFX_ID -1
#define OBJHITREACT_NO_REACTION_ANIM -1
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
  u8 pad63[0xAE - 0x63];
  u8 activeHitboxMode;
  u8 resetHitboxMode;
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

int objHitReact_update(int obj,ObjHitReactEntry *reactionEntries,u32 reactionEntryCount,
                       u32 reactionState,float *reactionStepScale);
void ObjHitReact_ResetActiveObjects(int objectCount);

#define objHitReactFn_80089890 objHitReact_update

#endif /* MAIN_OBJHITREACT_H_ */
