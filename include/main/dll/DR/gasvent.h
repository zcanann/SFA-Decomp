#ifndef MAIN_DLL_DR_GASVENT_H_
#define MAIN_DLL_DR_GASVENT_H_

#include "ghidra_import.h"

void gunpowderbarrel_triggerExplosion(int obj);
void FUN_801a1310(int param_1,float *param_2);
void FUN_801a136c(u32 param_1,u32 param_2,short param_3);
void FUN_801a1654(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
int gunpowderbarrel_getExtraSize(void);

#endif /* MAIN_DLL_DR_GASVENT_H_ */
