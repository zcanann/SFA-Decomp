#ifndef MAIN_DLL_DLL_138_H_
#define MAIN_DLL_DLL_138_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

struct PushableState;
void fn_80174A80(int param_1, struct PushableState *param_2);
void fn_80174BFC(int obj, int ext);
u32 fn_8017510C(short *param_1,short *param_2,ObjAnimUpdateState *animUpdate);
void fn_80175428(int obj);
int pushable_render2(int obj);
void pushable_modelMtxFn(int obj,int modelNo);
int pushable_func0B(int obj,int other);

#endif /* MAIN_DLL_DLL_138_H_ */
