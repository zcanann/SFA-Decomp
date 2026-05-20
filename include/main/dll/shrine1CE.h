#ifndef MAIN_DLL_SHRINE1CE_H_
#define MAIN_DLL_SHRINE1CE_H_

#include "ghidra_import.h"

void dll_19B_update(void);
void FUN_801cc5d4(undefined2 *param_1,int param_2);
void FUN_801cc5d8(int param_1);
void FUN_801cc600(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801cc868(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
int dll_19E_getExtraSize(void);
int dll_19E_func08(void);
void dll_19B_init(void);
void dll_19B_release(void);
void dll_19B_initialise(void);
int dll_19C_getExtraSize(void);
int dll_19C_func08(void);
void dll_19C_free(void);
void dll_19C_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_19C_hitDetect(void);
void dll_19C_update(void);
void dll_19C_init(int obj, u8 *initData);
void dll_19C_release(void);
void dll_19C_initialise(void);
int dll_19D_getExtraSize(void);
int dll_19D_func08(void);
void dll_19D_free(int obj);
void dll_19D_render(void);
void dll_19D_hitDetect(int obj);
void dll_19D_update(void);
void dll_19D_init(int obj);
void dll_19D_release(void);
void dll_19D_initialise(void);

#endif /* MAIN_DLL_SHRINE1CE_H_ */
