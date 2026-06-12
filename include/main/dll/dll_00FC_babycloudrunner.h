#ifndef MAIN_DLL_DLL_14C_H_
#define MAIN_DLL_DLL_14C_H_

#include "ghidra_import.h"

void dll_FC_update(int obj);
void dll_FC_init(int obj,int objDef);
void dll_FC_release_nop(void);
void dll_FC_initialise_nop(void);
void dll_14D_hitDetect(int obj);
void dll_14D_free_nop(void);
void dll_14D_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
int dll_14D_func08_ret_0(void);
int dll_14D_getExtraSize_ret_8(void);
void FUN_8017f0d4(int param_1);

#endif /* MAIN_DLL_DLL_14C_H_ */
