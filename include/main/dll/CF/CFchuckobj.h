#ifndef MAIN_DLL_CF_CFCHUCKOBJ_H_
#define MAIN_DLL_CF_CFCHUCKOBJ_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gAreaFXEmitObjDescriptor;
extern ObjectDescriptor12 gLFXEmitterObjDescriptor;

void fxemit_init(undefined4 param_1,undefined4 param_2,int param_3);
void FUN_8018f158(undefined4 param_1);
void FUN_8018f1b4(short *param_1);
void FUN_8018f4fc(undefined2 *param_1,int param_2);
void FUN_8018f500(void);
void FUN_8018f650(void);
undefined4 FUN_8018fca4(undefined4 param_1,undefined4 param_2,int param_3);
void FUN_8018fd14(void);
void FUN_8018fd48(int param_1);
void FUN_8018fec4(undefined2 *param_1,int param_2);
void FUN_8018fec8(undefined2 *param_1,undefined2 *param_2);
void FUN_8018ffbc(int param_1);
void FUN_80190004(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9);
void FUN_80190008(int param_1,int param_2);
void FUN_80190148(int param_1);
void FUN_801905c4(int param_1);

int areafxemit_getExtraSize(void);
int areafxemit_func08(void);
void areafxemit_free(int* obj);
void areafxemit_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void areafxemit_hitDetect(void);
void areafxemit_update(void);
void areafxemit_init(void);
void areafxemit_release(void);
void areafxemit_initialise(void);

int lfxemitter_func0B(int* obj);
int lfxemitter_setScale(void);
int lfxemitter_getExtraSize(void);
int lfxemitter_func08(void);
void lfxemitter_free(int* obj);
void lfxemitter_render(void);
void lfxemitter_hitDetect(void);
void lfxemitter_update(void);
void lfxemitter_init(void);
void lfxemitter_release(void);
void lfxemitter_initialise(void);

#endif /* MAIN_DLL_CF_CFCHUCKOBJ_H_ */
