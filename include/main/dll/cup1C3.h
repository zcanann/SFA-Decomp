#ifndef MAIN_DLL_CUP1C3_H_
#define MAIN_DLL_CUP1C3_H_

#include "ghidra_import.h"

void DBSH_Symbol_SeqFn(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801c9f44(void);
void FUN_801c9f64(int param_1);
void FUN_801c9f84(uint param_1);
void dbsh_symbol_render(undefined4 param_1);
void FUN_801ca13c(int param_1);
int dbsh_symbol_getExtraSize(void);
void dbsh_symbol_free(void);
void dbsh_symbol_update(void);
void dbsh_symbol_init(void);
int dll_197_getExtraSize(void);
int dll_197_func08(void);
void dll_197_render(void);
void dll_197_hitDetect(void);

#endif /* MAIN_DLL_CUP1C3_H_ */
