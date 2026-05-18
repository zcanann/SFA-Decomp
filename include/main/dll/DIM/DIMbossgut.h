#ifndef MAIN_DLL_DIM_DIMBOSSGUT_H_
#define MAIN_DLL_DIM_DIMBOSSGUT_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDIM_BossGutObjDescriptor;

int dimbossgut_getExtraSize(void);
int dimbossgut_func08(void);
void dimbossgut_free(void);
void dimbossgut_render(void);
void dimbossgut_hitDetect(void);
void dimbossgut_update(void);
void dimbossgut_init(void);
void dimbossgut_release(void);
void dimbossgut_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOSSGUT_H_ */
