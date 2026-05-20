#ifndef MAIN_DLL_ALPHAANIM_H_
#define MAIN_DLL_ALPHAANIM_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDoorLockObjDescriptor;
extern ObjectDescriptor gSeqObjectObjDescriptor;
extern ObjectDescriptor gSeqObj2ObjDescriptor;
extern ObjectDescriptor gIMMultiSeqObjDescriptor;

void doorlock_init(short *obj,int config);
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

int doorlock_getExtraSize(void);
void doorlock_free(void);
void doorlock_render(void);
void doorlock_update(void);

int seqobject_getExtraSize(void);
int seqobject_func08(void);
void seqobject_free(int x);
void seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void seqobject_update(void);
void seqobject_init(void);

int seqobj2_getExtraSize(void);
int seqobj2_func08(void);
void seqobj2_free(int x);
void seqobj2_render(void);
void seqobj2_hitDetect(void);
void seqobj2_update(void);
void seqobj2_init(int* obj, int* def);
void SeqObj2_release(void);
void SeqObj2_initialise(void);

int immultiseq_getExtraSize(void);
int immultiseq_func08(void);
void immultiseq_free(int x);
void immultiseq_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void immultiseq_hitDetect(void);
void immultiseq_update(void);
void immultiseq_init(void);
void immultiseq_release(void);
void immultiseq_initialise(void);

#endif /* MAIN_DLL_ALPHAANIM_H_ */
