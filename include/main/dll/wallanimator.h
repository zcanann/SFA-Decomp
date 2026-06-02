#ifndef MAIN_DLL_DLL_13B_H_
#define MAIN_DLL_DLL_13B_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

void FUN_80169360(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11);
int kaldachompme_getExtraSize(void);
int kaldachompme_getObjectTypeId(void);
void kaldachompme_free(void);
void kaldachompme_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                         undefined4 param_5,s8 renderFlag);
void kaldachompme_hitDetect(void);
void kaldachompme_update(int obj);
void kaldachompme_init(int obj,int params);
void kaldachompme_release(void);
void kaldachompme_initialise(void);
void FUN_801695e8(int param_1,byte param_2);
void FUN_8016980c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80169834(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_80169960(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_80169a44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_80169c04(int param_1);
void kaldachompspit_render(void *obj, int p2, int p3, int p4, int p5, s8 visible);

extern ObjectDescriptor gKaldaChompMeObjDescriptor;

#endif /* MAIN_DLL_DLL_13B_H_ */
