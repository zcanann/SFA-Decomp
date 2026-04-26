#ifndef MAIN_OBJHITREACT_H_
#define MAIN_OBJHITREACT_H_

#include "ghidra_import.h"

typedef struct ObjHitReactState {
  int activeHit;
  u8 pad04[0x58 - 0x04];
  s16 resetFrameCount;
  u8 pad5A[0x60 - 0x5A];
  s16 flags;
  u8 resetFlags;
} ObjHitReactState;

int objHitReact_update(int obj,void *entries,u32 entryCount,u32 reactionState,float *cooldown);
void ObjHitReact_ResetActiveObjects(int objectCount);

#define objHitReactFn_80089890 objHitReact_update

#endif /* MAIN_OBJHITREACT_H_ */
