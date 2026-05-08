#ifndef MAIN_DLL_DIM_DIMBOSS_H_
#define MAIN_DLL_DIM_DIMBOSS_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

typedef struct DIMbossObject DIMbossObject;

void DIMboss_updateState(DIMbossObject *param_1,undefined4 param_2,ObjAnimUpdateState *animUpdate);
void dimboss_func11(void);
int DIMboss_setScale(DIMbossObject *obj);
int DIMboss_getExtraSize(void);
int dimboss_func08(void);
void DIMboss_free(DIMbossObject *obj);
void DIMboss_render(DIMbossObject *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender);
void DIMboss_hitDetect(DIMbossObject *obj);
void dimboss_update2(DIMbossObject *obj);
void DIMboss_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                    ushort *param_9);
void dimboss_release(void);
void dimboss_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOSS_H_ */
