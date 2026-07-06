#ifndef MAIN_DLL_DIM_DIMBOSSGUT_H_
#define MAIN_DLL_DIM_DIMBOSSGUT_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gDIM_BossGutObjDescriptor;

int DIM_BossGut_getExtraSize(void);
int DIM_BossGut_getObjectTypeId(void);
void DIM_BossGut_free(void);
void DIM_BossGut_render(int obj,u32 param_2,u32 param_3,u32 param_4,
                       u32 param_5,char shouldRender);
void DIM_BossGut_hitDetect(void);
void DIM_BossGut_update(void);
void DIM_BossGut_init(void *obj);
int DIM_BossGut_SeqFn(int obj,int param_2,ObjAnimUpdateState *animUpdate);
void DIM_BossGut_release(void);
void DIM_BossGut_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOSSGUT_H_ */
