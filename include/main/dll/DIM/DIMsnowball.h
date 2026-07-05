#ifndef MAIN_DLL_DIM_DIMSNOWBALL_H_
#define MAIN_DLL_DIM_DIMSNOWBALL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gCCSharpclawPadObjDescriptor;
extern ObjectDescriptor gCCpedstalObjDescriptor;
extern ObjectDescriptor gCClevcontrolObjDescriptor;

void ccqueen_render(int *obj, int p2, int p3, int p4, int p5, s8 visible);
void ccqueen_update(int *obj);
int ccqueen_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void FUN_801aa684(int param_1);
void FUN_801aa6d8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801aa700(int param_1);
void FUN_801aa704(short *param_1,int param_2);
void FUN_801aa708(short *param_1);
void FUN_801aa750(int param_1);
void FUN_801aa820(short *param_1,int param_2);
u32 FUN_801aa8a4(int param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801aa984(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_801aaa6c(double param_1,int param_2,int param_3);
void FUN_801aab00(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_801aba9c(u32 param_1);
void FUN_801abcac(int param_1,int param_2);
void FUN_801abda4(int param_1,int param_2);
void FUN_801abe84(int param_1);
void FUN_801abf34(short *param_1,int param_2);
u32
FUN_801abf38(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,
            u32 param_10,ObjAnimUpdateState *animUpdate);
void FUN_801abfec(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_801ac040(int param_1);
void FUN_801ac060(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);

int ccsharpclawpad_getExtraSize(void);
void ccsharpclawpad_update(int obj);
void ccsharpclawpad_init(int* obj, int* def);
void cclightfoot_init(int* obj, int* def);
int cclevcontrol_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);

int ccpedstal_getExtraSize(void);
void ccpedstal_update(int obj);
void ccpedstal_init(int *obj, u8 *params);

int cclevcontrol_getExtraSize(void);
void cclevcontrol_free(void);
void cclevcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void cclevcontrol_update(int obj);
void cclevcontrol_init(int *obj);

#endif /* MAIN_DLL_DIM_DIMSNOWBALL_H_ */
