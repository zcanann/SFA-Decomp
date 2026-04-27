#ifndef MAIN_DLL_DIM_DIMBOSS_H_
#define MAIN_DLL_DIM_DIMBOSS_H_

#include "ghidra_import.h"

typedef struct DIMbossObject DIMbossObject;

void DIMboss_updateState(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                         undefined8 param_5,undefined8 param_6,undefined8 param_7,
                         undefined8 param_8,undefined4 param_9,undefined4 param_10,int param_11,
                         undefined4 param_12,undefined4 param_13,int param_14,int param_15,
                         undefined4 param_16);
void dimboss_func11(void);
int dimboss_setScale(DIMbossObject *obj);
int dimboss_getExtraSize(void);
int dimboss_func08(void);
void dimboss_free(DIMbossObject *obj);
void dimboss_render(DIMbossObject *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender);
void dimboss_hitDetect(DIMbossObject *obj);

#endif /* MAIN_DLL_DIM_DIMBOSS_H_ */
