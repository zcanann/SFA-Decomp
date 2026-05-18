#ifndef MAIN_DLL_DIM_DIMBOSSGUT_H_
#define MAIN_DLL_DIM_DIMBOSSGUT_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDIM_BossGutObjDescriptor;

int DIMbossgut_getExtraSize(void);
int DIMbossgut_func08(void);
void DIMbossgut_free(void);
void DIMbossgut_render(int obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                       undefined4 param_5,char shouldRender);
void DIMbossgut_hitDetect(void);
void DIMbossgut_update(void);
void DIMbossgut_init(void *obj);
int DIMbossgut_updateState(int obj, int param_2, void *state);
void DIMbossgut_release(void);
void DIMbossgut_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOSSGUT_H_ */
