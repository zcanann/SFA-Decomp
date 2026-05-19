#ifndef MAIN_DLL_LASER19F_H_
#define MAIN_DLL_LASER19F_H_

#include "ghidra_import.h"

void MMSH_Shrine_SeqFn(undefined4 param_1,undefined4 param_2,int param_3);
void FUN_801c4b14(ushort *param_1);
undefined4 FUN_801c4de0(int param_1);
int mmsh_shrine_getExtraSize(void);
int mmsh_shrine_func08(void);
void mmsh_shrine_free(int param_1);
void mmsh_shrine_render(int obj, undefined4 a2, undefined4 a3, undefined4 a4, undefined4 a5,
                        char flag);
void mmsh_shrine_hitDetect(void);
void mmsh_shrine_update(int param_1);

#endif /* MAIN_DLL_LASER19F_H_ */
