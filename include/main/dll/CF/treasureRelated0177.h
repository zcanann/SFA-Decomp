#ifndef MAIN_DLL_CF_TREASURERELATED0177_H_
#define MAIN_DLL_CF_TREASURERELATED0177_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gCampFireObjDescriptor;
extern ObjectDescriptor gKT_TorchObjDescriptor;
extern ObjectDescriptor gCFCrateObjDescriptor;

void dll_127_update(int obj);
void FUN_8018cdb0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_8018cf58(int param_1);
void dll_127_init(short *param_1,int param_2);
void FUN_8018d064(int param_1);
void FUN_8018d0b4(int param_1);
void FUN_8018d110(void);
int campfire_getExtraSize(void);
int campfire_func08(void);
void campfire_free(int obj);
void campfire_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible);
int kt_torch_getExtraSize(void);
int kt_torch_func08(void);
void kt_torch_free(void);
void kt_torch_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void kt_torch_hitDetect(void);
void kt_torch_update(int obj);
void kt_torch_release(void);
void kt_torch_initialise(void);
int cfccrate_getExtraSize(void);
int cfccrate_func08(void);
void cfccrate_free(int obj);

#endif /* MAIN_DLL_CF_TREASURERELATED0177_H_ */
