#ifndef MAIN_DLL_DIM_DIM2SNOWBALL_H_
#define MAIN_DLL_DIM_DIM2SNOWBALL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDIM_trickyObjDescriptor;
extern ObjectDescriptor12 gDIM2ConveyorObjDescriptor;
extern ObjectDescriptor gDIM2SnowBallObjDescriptor;

void dim_levelcontrol_update(int obj);
void FUN_801b6d24(int param_1);
void FUN_801b6eb8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b6ee0(u16 *param_1,int param_2);
void FUN_801b6f88(int param_1);
void FUN_801b6fa8(int param_1);
void FUN_801b7064(u32 param_1);
void FUN_801b728c(int param_1,int param_2);
void FUN_801b7478(int param_1);
void FUN_801b749c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b74c4(u32 param_1);
void FUN_801b7604(u16 *param_1,int param_2);
void FUN_801b7720(int param_1);
void FUN_801b7780(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b77a8(short *param_1);
void FUN_801b7c38(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,int param_10);
void FUN_801b7fa4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b7fcc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int *param_9);
void FUN_801b7fd0(u16 *param_1,int param_2);

int dim_tricky_getExtraSize(void);
int dim_tricky_getObjectTypeId(void);
void dim_tricky_free(void);
void dim_tricky_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim_tricky_hitDetect(void);
void dim_tricky_update(int* obj);
void dim_tricky_init(int *obj);

void dim2conveyor_setScale(int *obj, int unused, f32 *outX, f32 *outY);
int dim2conveyor_getExtraSize(void);
int dim2conveyor_getObjectTypeId(void);
void dim2conveyor_free(int obj);
void dim2conveyor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2conveyor_hitDetect(void);
void dim2conveyor_update(int* obj);
void dim2conveyor_init(int* obj, u8* params);
void dim2conveyor_release(void);
void dim2conveyor_initialise(void);

int dim2snowball_getExtraSize(void);
int dim2snowball_getObjectTypeId(void);
void dim2snowball_free(void);
void dim2snowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2snowball_hitDetect(void);
void dim2snowball_update(int* obj);
void dim2snowball_init(int* obj, int* def);
void dim2snowball_release(void);
void dim2snowball_initialise(void);
int dll_1DA_getExtraSize(void);
int dll_1DA_getObjectTypeId(void);
void dll_1DA_free(void);
void dll_1DA_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1DA_hitDetect(int obj);
int dll_1CF_getExtraSize(void);
int dll_1CF_getObjectTypeId(void);
void dll_1CF_free(void);
void dll_1CF_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1CF_hitDetect(void);
void dll_1CF_update(void);
void dll_1CF_release(void);
void dll_1CF_initialise(void);
int dll_1D6_getExtraSize(void);
int dll_1D6_getObjectTypeId(void);
void dll_1D6_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1D6_hitDetect(void);
void dll_1D6_release(void);
void dll_1D6_initialise(void);

#endif /* MAIN_DLL_DIM_DIM2SNOWBALL_H_ */
