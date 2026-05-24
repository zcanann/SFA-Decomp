#ifndef MAIN_DLL_DIM_DIMLAVASMASH_H_
#define MAIN_DLL_DIM_DIMLAVASMASH_H_

#include "ghidra_import.h"

void dimlogfire_update(int obj);
undefined4 FUN_801b09dc(uint param_1,undefined4 param_2,int param_3);
void FUN_801b0ae8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void dimlogfire_init(int obj,int def);
void FUN_801b0c9c(uint param_1);
void FUN_801b0fd4(int param_1,int param_2);
int dimsnowball_getExtraSize(void);
int dimsnowball_getObjectTypeId(void);
void dimsnowball_free(void);
void dimsnowball_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void dimsnowball_hitDetect(int *obj);
void dimsnowball_update(int obj);

#endif /* MAIN_DLL_DIM_DIMLAVASMASH_H_ */
