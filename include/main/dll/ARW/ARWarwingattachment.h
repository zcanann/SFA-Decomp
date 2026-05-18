#ifndef MAIN_DLL_ARW_ARWARWINGATTACHMENT_H_
#define MAIN_DLL_ARW_ARWARWINGATTACHMENT_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gPressureSwitchObjDescriptor;
extern ObjectDescriptor gWM_LaserTargetObjDescriptor;

void LaserBeam_update(int param_1);
void FUN_801f0cb8(int param_1);
void FUN_801f0cf0(int param_1);
void FUN_801f0d8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801f0d90(int param_1);
void FUN_801f0de8(uint param_1);
void FUN_801f0dec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801f10ac(void);
void FUN_801f10d8(void);
void FUN_801f10dc(int param_1);
void FUN_801f1104(void);
void FUN_801f15ac(undefined2 *param_1,int param_2);
void FUN_801f15b0(int param_1);
void FUN_801f1634(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_801f1934(int param_1);
void FUN_801f195c(int param_1);
void FUN_801f1a64(int param_1,int param_2);
void FUN_801f1ac0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801f1d3c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801f23c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
undefined4 FUN_801f25b4(int param_1,undefined4 param_2,int param_3);
undefined4 FUN_801f26a8(int param_1,undefined4 param_2,int param_3);
void FUN_801f284c(void);
void FUN_801f28d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9);
void FUN_801f28d8(undefined2 *param_1,undefined2 *param_2);
void FUN_801f28dc(int param_1);
void FUN_801f2904(uint param_1);
void FUN_801f2ac8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_801f2b94(short *param_1);

int pressureswitch_getExtraSize(void);
int pressureswitch_func08(void);
void pressureswitch_free(void);
void pressureswitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void pressureswitch_hitDetect(void);
void pressureswitch_update(void);
void pressureswitch_init(void);
void pressureswitch_release(void);
void pressureswitch_initialise(void);

int wmlasertarget_getExtraSize(void);
int wmlasertarget_func08(void);
void wmlasertarget_free(void);
void wmlasertarget_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void wmlasertarget_hitDetect(void);
void wmlasertarget_update(void);
void wmlasertarget_init(void);
void wmlasertarget_release(void);
void wmlasertarget_initialise(void);

#endif /* MAIN_DLL_ARW_ARWARWINGATTACHMENT_H_ */
