#ifndef MAIN_DLL_DR_CANNONTARGETCONTROL_H_
#define MAIN_DLL_DR_CANNONTARGETCONTROL_H_

#include "ghidra_import.h"

void gunpowderbarrel_hitDetect(int param_1);
void FUN_801a1df8(int param_1,int param_2);
void FUN_801a1ec4(u32 param_1,u32 param_2,u32 param_3,u32 param_4,
                 u32 param_5,u32 param_6);
void FUN_801a1fb8(int *param_1);
void FUN_801a2350(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
int blasted_getExtraSize(void);
int blasted_getObjectTypeId(void);
void blasted_free(void);
void blasted_render(int *obj, int p2, int p3, int p4, int p5, s8 visible);
void blasted_hitDetect(void);

#endif /* MAIN_DLL_DR_CANNONTARGETCONTROL_H_ */
