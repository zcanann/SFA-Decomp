#ifndef MAIN_DLL_CUP1C3_H_
#define MAIN_DLL_CUP1C3_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

int DBSH_Symbol_SeqFn(int obj, int anim, ObjAnimUpdateState *animUpdate);
void FUN_801c9f44(void);
void FUN_801c9f64(int param_1);
void dbsh_symbol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FUN_801ca13c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
int dbsh_symbol_getExtraSize(void);
void dbsh_symbol_free(void);
void dbsh_symbol_update(int obj);
void dbsh_symbol_init(int* obj);
int dll_197_getExtraSize(void);
int dll_197_getObjectTypeId(void);
void dll_197_free(int obj);
void dll_197_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_197_hitDetect(void);
void dll_197_update(int obj);

#endif /* MAIN_DLL_CUP1C3_H_ */
