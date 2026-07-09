#ifndef MAIN_DLL_DLL_138_H_
#define MAIN_DLL_DLL_138_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

struct PushableState;
void fn_80174A80(struct GameObject *param_1, struct PushableState *param_2);
void fn_80174BFC(int obj, int ext);
u32 pushable_SeqFn(short *param_1,short *param_2,ObjAnimUpdateState *animUpdate);
void pushable_handleMsgs(int obj);
int pushable_render2(struct GameObject *obj);
void pushable_modelMtxFn(struct GameObject *obj,int modelNo);
int pushable_func0B(struct GameObject *obj,int other);

#endif /* MAIN_DLL_DLL_138_H_ */
