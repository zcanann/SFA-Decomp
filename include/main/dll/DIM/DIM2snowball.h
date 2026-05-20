#ifndef MAIN_DLL_DIM_DIM2SNOWBALL_H_
#define MAIN_DLL_DIM_DIM2SNOWBALL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDIM_trickyObjDescriptor;
extern ObjectDescriptor12 gDIM2ConveyorObjDescriptor;
extern ObjectDescriptor gDIM2SnowBallObjDescriptor;

void dim_levelcontrol_update(void);
void FUN_801b649c(int param_1);
void FUN_801b64c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_801b6d24(int param_1);
void FUN_801b6eb8(int param_1);
void FUN_801b6ee0(undefined2 *param_1,int param_2);
void FUN_801b6f88(int param_1);
void FUN_801b6fa8(int param_1);
void FUN_801b7064(uint param_1);
void FUN_801b728c(int param_1,int param_2);
void FUN_801b7314(int param_1,undefined4 param_2,float *param_3,float *param_4);
void FUN_801b7478(int param_1);
void FUN_801b749c(int param_1);
void FUN_801b74c4(uint param_1);
void FUN_801b7604(undefined2 *param_1,int param_2);
void FUN_801b7720(int param_1);
void FUN_801b7780(int param_1);
void FUN_801b77a8(short *param_1);
void FUN_801b7c38(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10);
void FUN_801b7fa4(int param_1);
void FUN_801b7fcc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9);
void FUN_801b7fd0(undefined2 *param_1,int param_2);

int dim_tricky_getExtraSize(void);
int dim_tricky_func08(void);
void dim_tricky_free(void);
void dim_tricky_render(void);
void dim_tricky_hitDetect(void);
void dim_tricky_update(int* obj);
void dim_tricky_init(int *obj);

void dim2conveyor_setScale(void);
int dim2conveyor_getExtraSize(void);
int dim2conveyor_func08(void);
void dim2conveyor_free(int obj);
void dim2conveyor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2conveyor_hitDetect(void);
void dim2conveyor_update(void);
void dim2conveyor_init(void);
void dim2conveyor_release(void);
void dim2conveyor_initialise(void);

int dim2snowball_getExtraSize(void);
int dim2snowball_func08(void);
void dim2snowball_free(void);
void dim2snowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2snowball_hitDetect(void);
void dim2snowball_update(void);
void dim2snowball_init(int* obj, int* def);
void dim2snowball_release(void);
void dim2snowball_initialise(void);
int dll_1DA_getExtraSize(void);
int dll_1DA_func08(void);
void dll_1DA_free(void);
void dll_1DA_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1DA_hitDetect(int obj);
int dll_1CF_getExtraSize(void);
int dll_1CF_func08(void);
void dll_1CF_free(void);
void dll_1CF_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1CF_hitDetect(void);
void dll_1CF_update(void);
void dll_1CF_release(void);
void dll_1CF_initialise(void);
int dll_1D6_getExtraSize(void);
int dll_1D6_func08(void);
void dll_1D6_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1D6_hitDetect(void);
void dll_1D6_release(void);
void dll_1D6_initialise(void);

#endif /* MAIN_DLL_DIM_DIM2SNOWBALL_H_ */
