#ifndef MAIN_DLL_DIM_DIMBOSS_H_
#define MAIN_DLL_DIM_DIMBOSS_H_

#include "ghidra_import.h"

typedef struct DIMbossObject DIMbossObject;

void DIMboss_updateState(DIMbossObject *param_1,undefined4 param_2,int param_3);
void dimboss_func11(void);
int DIMboss_setScale(DIMbossObject *obj);
int DIMboss_getExtraSize(void);
int dimboss_func08(void);
void DIMboss_free(DIMbossObject *obj);
void DIMboss_render(DIMbossObject *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender);
void DIMboss_hitDetect(DIMbossObject *obj);

#endif /* MAIN_DLL_DIM_DIMBOSS_H_ */
