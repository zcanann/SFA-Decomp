#ifndef MAIN_DLL_DR_CANNONTARGETCONTROL_H_
#define MAIN_DLL_DR_CANNONTARGETCONTROL_H_

#include "ghidra_import.h"

void gunpowderbarrel_hitDetect(int param_1);
void FUN_801a1df8(int param_1,int param_2);
void FUN_801a1ec4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6);
void FUN_801a1fb8(int *param_1);
void FUN_801a2350(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
int blasted_getExtraSize(void);
int blasted_func08(void);
void blasted_free(void);
void blasted_hitDetect(void);

#endif /* MAIN_DLL_DR_CANNONTARGETCONTROL_H_ */
