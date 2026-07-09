#ifndef MAIN_DLL_DLL_14C_H_
#define MAIN_DLL_DLL_14C_H_

#include "ghidra_import.h"

void dll_FC_update(int obj);
void dll_FC_init(struct GameObject* obj, int objDef);
void dll_FC_release_nop(void);
void dll_FC_initialise_nop(void);
void dll_FD_hitDetect(int obj);
void dll_FD_free(void);
void dll_FD_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
int dll_14D_func08_ret_0(void);
int dll_FD_getExtraSize(void);
void FUN_8017f0d4(int param_1);

/* extern-cleanup: defining-file public prototypes */
void dll_FC_hitDetect(int* obj);

#endif /* MAIN_DLL_DLL_14C_H_ */
