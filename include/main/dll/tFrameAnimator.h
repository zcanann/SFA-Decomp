#ifndef MAIN_DLL_TFRAMEANIMATOR_H_
#define MAIN_DLL_TFRAMEANIMATOR_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

u32 SidekickBall_init(struct GameObject* obj);
int LevelName_SeqFn(struct GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void LevelName_init(struct GameObject* obj, int objDef);
extern ObjectDescriptor gAreaObjDescriptor;

#endif /* MAIN_DLL_TFRAMEANIMATOR_H_ */
