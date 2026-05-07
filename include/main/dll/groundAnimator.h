#ifndef MAIN_DLL_GROUNDANIMATOR_H_
#define MAIN_DLL_GROUNDANIMATOR_H_

#include "ghidra_import.h"

void fn_8017D0D4(int obj);
void fn_8017D278(short *obj,int mapData);
void fn_8017D374(void);
void fn_8017D378(void);
int wm_column_getExtraSize(void);
int wm_column_func08(void);
void wm_column_free(int obj);
void wm_column_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void wm_column_hitDetect(void);
void wm_column_update(int obj);
void wm_column_init(short *obj,int mapData);
void wm_column_release(void);
void wm_column_initialise(void);
void appleontree_func0B(int obj,float *pos);
void FUN_8017db40(uint param_1,int param_2);
void FUN_8017de58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_8017e0f8(void);
void FUN_8017e12c(int param_1);
undefined4 FUN_8017e15c(double param_1,undefined2 *param_2,int param_3);
undefined4 FUN_8017e3c0(double param_1,undefined2 *param_2,int param_3);

#endif /* MAIN_DLL_GROUNDANIMATOR_H_ */
