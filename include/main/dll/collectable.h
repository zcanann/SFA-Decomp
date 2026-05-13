#ifndef MAIN_DLL_COLLECTABLE_H_
#define MAIN_DLL_COLLECTABLE_H_

#include "ghidra_import.h"

void FUN_80144e40(int param_1,int param_2);
int FUN_80145120(int param_1,int param_2);
void FUN_80145230(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int *param_10,int param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16);
void FUN_801455e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_801457a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
int fn_801451D8(int obj,int state);
void fn_80144F50(int obj,int state);
void FUN_80145ea4(int param_1);
void FUN_80145ee8(int param_1,int param_2,int param_3);
int fn_80145828(int *obj,int targetObj);
void fn_801458BC(int *obj,int commandEnabled,int targetObj);
void sideCommandEnable(int param_1,int param_2,int param_3,int param_4);
void FUN_801460b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
uint FUN_80146874(void);
void Tricky_destroy(int obj,int shouldKeepFlameChildren);
void fn_80148C18(int obj,int state);
void fn_80148D8C(int obj,int state);
int fn_80149CEC(int obj,int state,u32 spawnBits,u32 useAltMode,u32 mode);
int fn_8014A150(int obj,int state,void *from,void *to);
void fn_8014A304(float radius,int obj,int state);
void fn_8014A5FC(int obj,int state);
void fn_8014A86C(int obj,int state,float *nearestFloorY,float *nearestSpecialY);
void fn_801463BC(int obj,int param_2,int param_3,int param_4,int param_5,char doRender);
void fn_8014658C(int obj);
void FUN_80146f94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80146f98(int param_1);
void FUN_80146f9c(void);
void FUN_80146fa0(void);
void fn_8014A058(int obj,int state);
void FUN_80146fa4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_80147218(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_8014721c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11);
void FUN_80147220(double param_1,int param_2,uint param_3,undefined2 param_4);
void FUN_80147314(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801476cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_80147884(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,float *param_12);
void FUN_80147a70(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80147d2c(int param_1,int param_2);

#endif /* MAIN_DLL_COLLECTABLE_H_ */
