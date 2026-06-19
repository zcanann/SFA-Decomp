#ifndef MAIN_DLL_TFRAMEANIMATOR_H_
#define MAIN_DLL_TFRAMEANIMATOR_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

u32 sidekickball_init(int obj);
int levelname_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void levelname_init(int obj, int objDef);
extern ObjectDescriptor gAreaObjDescriptor;

#endif /* MAIN_DLL_TFRAMEANIMATOR_H_ */
