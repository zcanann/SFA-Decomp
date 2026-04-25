#ifndef MAIN_DLL_DIM_DIMBOSS_H_
#define MAIN_DLL_DIM_DIMBOSS_H_

#include "ghidra_import.h"

void DIMboss_updateState(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                         undefined8 param_5,undefined8 param_6,undefined8 param_7,
                         undefined8 param_8,undefined4 param_9,undefined4 param_10,int param_11,
                         undefined4 param_12,undefined4 param_13,int param_14,int param_15,
                         undefined4 param_16);
void dimboss_func11(void);
int dimboss_setScale(int param_1);
int dimboss_getExtraSize(void);
int dimboss_func08(void);
void dimboss_free(int param_1);
void dimboss_render(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender);
void dimboss_hitDetect(int param_1);

#endif /* MAIN_DLL_DIM_DIMBOSS_H_ */
