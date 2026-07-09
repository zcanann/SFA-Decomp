#ifndef MAIN_DLL_TFRAMEANIMATOR_H_
#define MAIN_DLL_TFRAMEANIMATOR_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

u32 SidekickBall_init(GameObject* obj);
int LevelName_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void LevelName_init(GameObject* obj, int objDef);
extern ObjectDescriptor gAreaObjDescriptor;

#endif /* MAIN_DLL_TFRAMEANIMATOR_H_ */
