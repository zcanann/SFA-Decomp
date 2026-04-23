#ifndef MAIN_DLL_CF_LASER_H_
#define MAIN_DLL_CF_LASER_H_

#include "ghidra_import.h"

void laser_init(void);
void FUN_802096fc(int param_1);
void laser_initialise(undefined2 *param_1,int param_2);
undefined4
laser_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
             undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
             undefined4 param_10,int param_11,int param_12,undefined4 param_13,
             undefined4 param_14,undefined4 param_15,undefined4 param_16);
void laser_render(int param_1);
void laser_release(undefined4 param_1);
void laser_hitDetect(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                     undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                     int param_9);
void FUN_80209e58(void);
void FUN_80209e8c(void);
void FUN_80209eb8(void);
void FUN_80209f00(void);
void FUN_80209f30(void);
void FUN_80209f5c(void);
void laser_free(int param_1);

#endif /* MAIN_DLL_CF_LASER_H_ */
