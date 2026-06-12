#ifndef MAIN_DLL_CREATOR1C6_H_
#define MAIN_DLL_CREATOR1C6_H_

#include "ghidra_import.h"
#include "main/dll/dll_0195_dbshshrine.h"
#include "main/objanim_update.h"

int fn_801C8EBC(int obj, undefined4 unused, ObjAnimUpdateState *animUpdate);
void FUN_801c9018(ushort *param_1);
int dbsh_shrine_getExtraSize(void);
int dbsh_shrine_getObjectTypeId(void);
void dbsh_shrine_free(int obj);
void dbsh_shrine_render(int obj,undefined4 p2,undefined4 p3,undefined4 p4,undefined4 p5,s8 visible);
void dbsh_shrine_hitDetect(void);
void dbsh_shrine_init(DbshShrineObject *obj);
void dbsh_shrine_release(void);
void dbsh_shrine_initialise(void);

#endif /* MAIN_DLL_CREATOR1C6_H_ */
