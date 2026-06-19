#ifndef MAIN_DLL_DIM_DIMLAVASMASH_H_
#define MAIN_DLL_DIM_DIMLAVASMASH_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void dimlogfire_update(int obj);
u32 FUN_801b09dc(u32 param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801b0ae8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void dimlogfire_init(int obj,int def);
int dimsnowball_getExtraSize(void);
int dimsnowball_getObjectTypeId(void);
void dimsnowball_free(void);
void dimsnowball_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void dimsnowball_hitDetect(int *obj);
void dimsnowball_update(int obj);

#endif /* MAIN_DLL_DIM_DIMLAVASMASH_H_ */
