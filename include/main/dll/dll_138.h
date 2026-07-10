#ifndef MAIN_DLL_DLL_138_H_
#define MAIN_DLL_DLL_138_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"

struct PushableState;
void fn_80174A80(GameObject* param_1, struct PushableState* param_2);
void fn_80174BFC(GameObject* obj, int ext);
u32 pushable_SeqFn(short* param_1, short* param_2, ObjAnimUpdateState* animUpdate);
void pushable_handleMsgs(GameObject* obj);
int pushable_render2(GameObject* obj);
void pushable_modelMtxFn(GameObject* obj, int modelNo);
int pushable_func0B(GameObject* obj, int other);

#endif /* MAIN_DLL_DLL_138_H_ */
