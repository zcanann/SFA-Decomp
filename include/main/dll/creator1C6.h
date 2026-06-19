#ifndef MAIN_DLL_CREATOR1C6_H_
#define MAIN_DLL_CREATOR1C6_H_

#include "ghidra_import.h"
#include "main/dll/dll_0195_dbshshrine.h"
#include "main/objanim_update.h"

int fn_801C8EBC(int obj, u32 unused, ObjAnimUpdateState *animUpdate);
void FUN_801c9018(u16 *param_1);
int dbsh_shrine_getExtraSize(void);
int dbsh_shrine_getObjectTypeId(void);
void dbsh_shrine_free(int obj);
void dbsh_shrine_render(int obj,u32 p2,u32 p3,u32 p4,u32 p5,s8 visible);
void dbsh_shrine_hitDetect(void);
void dbsh_shrine_init(DbshShrineObject *obj);
void dbsh_shrine_release(void);
void dbsh_shrine_initialise(void);

#endif /* MAIN_DLL_CREATOR1C6_H_ */
