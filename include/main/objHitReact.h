#ifndef MAIN_OBJHITREACT_H_
#define MAIN_OBJHITREACT_H_

#include "ghidra_import.h"

typedef struct ObjHitReactEntry ObjHitReactEntry;

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
  s16 clearVolumeA;
  s16 clearVolumeB;
  s16 reactionAnim;
  u8 pad06[2];
  s8 hitFxMode;
  u8 pad09[3];
  f32 cooldown;
  u8 pad10[4];
};

int objHitReact_update(int obj,ObjHitReactEntry *entries,u32 entryCount,u32 reactionState,float *cooldown);
void ObjHitReact_ResetActiveObjects(int objectCount);

#define objHitReactFn_80089890 objHitReact_update

#endif /* MAIN_OBJHITREACT_H_ */
