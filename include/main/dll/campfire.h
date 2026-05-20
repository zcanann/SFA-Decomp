#ifndef MAIN_DLL_CAMPFIRE_H_
#define MAIN_DLL_CAMPFIRE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

void kaldaChomFn_8016821c(int param_1,int *param_2);
void kaldaChomFn_80168374(int param_1,int param_2,char param_3);
void fn_8016855C(undefined4 param_1,undefined4 param_2,int param_3);
void fn_8016874C(undefined4 param_1,undefined4 param_2,int param_3);
void kaldachom_func0B(void);
s16 kaldachom_setScale(int *obj);
int kaldachom_getExtraSize(void);
int kaldachom_func08(void);
void kaldachom_free(int param_1);
void kaldachom_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                      undefined4 param_5,char param_6);
void kaldachom_hitDetect(void);
void kaldachom_update(int param_1);
void kaldachom_init(undefined4 param_1,undefined4 param_2,int param_3);
void kaldachom_release(void);
void kaldachom_initialise(void);

extern ObjectDescriptor12 gKaldaChomObjDescriptor;

#endif /* MAIN_DLL_CAMPFIRE_H_ */
