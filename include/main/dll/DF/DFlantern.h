#ifndef MAIN_DLL_DF_DFLANTERN_H_
#define MAIN_DLL_DF_DFLANTERN_H_

#include "ghidra_import.h"

void FUN_801c282c(int param_1);
void FUN_801c2d08(int param_1,int param_2);
void FUN_801c2d0c(void);
void FUN_801c2d44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
undefined4 FUN_801c2e58(int param_1);
void FUN_801c2f68(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_801c2f90(int param_1,int param_2);
int fn_801C2C68(int obj,int unused,void *seq);
void dfsh_door2speci_free(void);
void dfsh_door2speci_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void dfsh_door2speci_hitDetect(void);
void dfsh_door2speci_update(void);
void dfsh_door2speci_init(int obj,int def);
void dfsh_door2speci_release(void);
void dfsh_door2speci_initialise(void);
int dfsh_shrine_getExtraSize(void);
int dfsh_shrine_getObjectTypeId(void);
void dfsh_shrine_free(int obj);

#endif /* MAIN_DLL_DF_DFLANTERN_H_ */
