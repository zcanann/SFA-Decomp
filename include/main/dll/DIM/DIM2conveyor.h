#ifndef MAIN_DLL_DIM_DIM2CONVEYOR_H_
#define MAIN_DLL_DIM_DIM2CONVEYOR_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDIMBridgeCogMaiObjDescriptor;
extern ObjectDescriptor12 gDIMDismountPointObjDescriptor;

void FUN_801b3658(undefined2 *param_1,int param_2);
void FUN_801b365c(undefined4 param_1,undefined4 param_2,uint param_3);
uint FUN_801b376c(uint param_1,undefined4 param_2,int param_3);
void FUN_801b3a28(int param_1);
void FUN_dropped_dimbridgecogmai_release(int param_1);
void FUN_801b3af0(undefined2 *param_1,int param_2);
undefined4 FUN_801b3af4(int param_1,undefined4 param_2,int param_3);
void FUN_dropped_dimdismountpoint_func08(int param_1);
void FUN_801b3b7c(int param_1);
void FUN_801b3ba4(int param_1);
void FUN_801b3d1c(short *param_1,int param_2);

int dimbridgecogmai_getExtraSize(void);
int dimbridgecogmai_func08(void);
void dimbridgecogmai_free(int obj);
void dimbridgecogmai_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimbridgecogmai_hitDetect(void);
void dimbridgecogmai_update(void);
void dimbridgecogmai_init(void);
void dimbridgecogmai_initialise(void);

void dimdismountpoint_func11(int obj, int flag);
void dimdismountpoint_setScale(void);
int dimdismountpoint_getExtraSize(void);
void dimdismountpoint_free(int obj);
void dimdismountpoint_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void dimdismountpoint_hitDetect(void);
void dimdismountpoint_update(void);
void dimdismountpoint_init(void);
void dimdismountpoint_release(void);
void dimdismountpoint_initialise(void);

#endif /* MAIN_DLL_DIM_DIM2CONVEYOR_H_ */
