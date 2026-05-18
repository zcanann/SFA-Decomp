#ifndef MAIN_DLL_DIM_DIM2PROJROCK_H_
#define MAIN_DLL_DIM_DIM2PROJROCK_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDIM2IceFloeObjDescriptor;
extern ObjectDescriptor gDIM2IcicleObjDescriptor;
extern ObjectDescriptor12 gDIM2LavaControlObjDescriptor;

void FUN_801b8860(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_801b8c60(int param_1);
void FUN_801b8c88(uint param_1);
void FUN_801b8d0c(int *param_1);
void FUN_801b932c(int param_1);
void FUN_801b9354(uint param_1);
void FUN_801b968c(undefined2 *param_1,int param_2);
void FUN_801b9700(int param_1);
void FUN_801b9728(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801b972c(undefined2 *param_1,int param_2);
void FUN_801b98ec(int param_1);
void FUN_801b9914(uint param_1);
void FUN_801b9c2c(undefined2 *param_1,int param_2);
void FUN_801b9cc4(int param_1);
void FUN_801b9d2c(void);
void FUN_801b9d64(int param_1);
void FUN_801b9d8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801ba288(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_801ba434(int param_1);
void FUN_801ba45c(int param_1);

int dim2icefloe_getExtraSize(void);
int dim2icefloe_func08(void);
void dim2icefloe_free(void);
void dim2icefloe_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2icefloe_hitDetect(void);
void dim2icefloe_update(void);
void dim2icefloe_init(void);
void dim2icefloe_release(void);
void dim2icefloe_initialise(void);

int dim2icicle_getExtraSize(void);
int dim2icicle_func08(void);
void dim2icicle_free(void);
void dim2icicle_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2icicle_hitDetect(void);
void dim2icicle_update(void);
void dim2icicle_init(void);
void dim2icicle_release(void);
void dim2icicle_initialise(void);

void dim2lavacontrol_setScale(void);
int dim2lavacontrol_getExtraSize(void);
void dim2lavacontrol_free(void);
void dim2lavacontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2lavacontrol_update(void);
void dim2lavacontrol_init(void);

#endif /* MAIN_DLL_DIM_DIM2PROJROCK_H_ */
