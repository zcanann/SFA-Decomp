#ifndef MAIN_DLL_ALPHAANIM_H_
#define MAIN_DLL_ALPHAANIM_H_

#include "ghidra_import.h"

undefined4 doorlock_init(int param_1,undefined4 param_2,int param_3);
void FUN_8017c230(int param_1);
void FUN_8017c254(int param_1);
void FUN_8017c29c(int param_1);
void FUN_8017c5c0(short *param_1,int param_2);
void FUN_8017c5c4(int param_1);
undefined4
FUN_8017c608(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,int param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16);
void seqObject_free(int param_1);
void seqObject_render(int param_1);
void seqObject_update(int param_1);
void seqObject_init(short *param_1,int param_2);
undefined4 FUN_8017ca44(int param_1,undefined4 param_2,int param_3);
void seqObj2_free(int param_1);
void seqObj2_update(int param_1);
void seqObj2_init(short *param_1,int param_2);

#endif /* MAIN_DLL_ALPHAANIM_H_ */
