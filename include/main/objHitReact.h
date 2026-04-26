#ifndef MAIN_OBJHITREACT_H_
#define MAIN_OBJHITREACT_H_

#include "ghidra_import.h"

u8 objHitReact_update(int obj,void *entries,u32 entryCount,u32 reactionState,float *cooldown);
void ObjHitReact_ResetActiveObjects(int objectCount);

#define objHitReactFn_80089890 objHitReact_update

#endif /* MAIN_OBJHITREACT_H_ */
