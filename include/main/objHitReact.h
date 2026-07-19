#ifndef MAIN_OBJHITREACT_H_
#define MAIN_OBJHITREACT_H_

#include "main/objHitReact_types.h"

u8 ObjHitReact_Update(int obj,ObjHitReactEntry *reactionEntryTable,u32 reactionEntryCount,
                      u32 reactionState,float *reactionStepScale);

#endif /* MAIN_OBJHITREACT_H_ */
