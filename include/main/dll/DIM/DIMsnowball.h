#ifndef MAIN_DLL_DIM_DIMSNOWBALL_H_
#define MAIN_DLL_DIM_DIMSNOWBALL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gCCSharpclawPadObjDescriptor;
extern ObjectDescriptor gCCpedstalObjDescriptor;
extern ObjectDescriptor gCClevcontrolObjDescriptor;

void ccqueen_render(void);
void FUN_801aa684(int param_1);
void FUN_801aa6d8(int param_1);
void FUN_801aa700(int param_1);
void FUN_801aa704(short *param_1,int param_2);
void FUN_801aa708(short *param_1);
void FUN_801aa750(int param_1);
void FUN_801aa820(short *param_1,int param_2);
undefined4 FUN_801aa8a4(int param_1,undefined4 param_2,int param_3);
void FUN_801aa984(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_801aaa6c(double param_1,int param_2,int param_3);
void FUN_801aab00(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_801aba9c(uint param_1);
void FUN_801abcac(int param_1,int param_2);
void FUN_801abda4(int param_1,int param_2);
void FUN_801abe84(int param_1);
void FUN_801abf34(short *param_1,int param_2);
undefined4
FUN_801abf38(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,int param_11);
void FUN_801abfec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_801ac040(int param_1);
void FUN_801ac060(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);

int ccsharpclawpad_getExtraSize(void);
void ccsharpclawpad_update(void);
void ccsharpclawpad_init(int* obj, int* def);
void cclightfoot_init(int* obj, int* def);
int fn_801ABA84(int p1, int p2, unsigned char* state);

int ccpedstal_getExtraSize(void);
void ccpedstal_update(void);
void ccpedstal_init(void);

int cclevcontrol_getExtraSize(void);
void cclevcontrol_free(void);
void cclevcontrol_render(void);
void cclevcontrol_update(void);
void cclevcontrol_init(void);

#endif /* MAIN_DLL_DIM_DIMSNOWBALL_H_ */
