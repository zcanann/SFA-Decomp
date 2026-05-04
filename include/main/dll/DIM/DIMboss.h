#ifndef MAIN_DLL_DIM_DIMBOSS_H_
#define MAIN_DLL_DIM_DIMBOSS_H_

#include "ghidra_import.h"

typedef struct DIMbossObject DIMbossObject;

void DIMboss_updateState(DIMbossObject *param_1,undefined4 param_2,int param_3);
void dimboss_func11(void);
int dimboss_setScale(DIMbossObject *obj);
int dimboss_getExtraSize(void);
int dimboss_func08(void);
void dimboss_free(DIMbossObject *obj);
void dimboss_render(DIMbossObject *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender);
void dimboss_hitDetect(DIMbossObject *obj);

#endif /* MAIN_DLL_DIM_DIMBOSS_H_ */
