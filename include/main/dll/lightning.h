#ifndef MAIN_DLL_DLL_141_H_
#define MAIN_DLL_DLL_141_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gEffectBoxObjDescriptor;

void MagicDust_update(int param_1);
void MagicDust_init(int param_1,int param_2);
void FUN_80173b84(int param_1,int param_2);
void FUN_80173fdc(int param_1);
void FUN_80173ffc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80174024(int param_1);
void FUN_8017437c(int param_1,int param_2);
u32 FUN_801743f0(u32 param_1,int param_2);
void FUN_80174524(int param_1,int param_2);
int EffectBox_getExtraSize(void);
int EffectBox_getObjectTypeId(void);
void EffectBox_free(void);
void EffectBox_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void EffectBox_hitDetect(void);
void EffectBox_release(void);
void EffectBox_initialise(void);

#endif /* MAIN_DLL_DLL_141_H_ */
