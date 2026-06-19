#ifndef MAIN_DLL_MMP_MMP_LEVELCONTROL_H_
#define MAIN_DLL_MMP_MMP_LEVELCONTROL_H_

#include "ghidra_import.h"

#define WALLANIMATOR_DONE_TIMER 3000
#define WALLANIMATOR_GROUP_PRIMARY 0x23
#define WALLANIMATOR_GROUP_SECONDARY 0x31
#define WALLANIMATOR_NEARBY_GROUP 5
#define WALLANIMATOR_RUNTIME_ACTIVE_FLAG 0x80
#define WALLANIMATOR_COMPLETE_SFX 0x109

f32 wallanimator_setScale(int obj,int desc);
void FUN_80194544(int param_1);
void FUN_801945fc(int param_1,int param_2);
void FUN_801946b8(void);
void FUN_80194874(int param_1);
void FUN_801948b0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801948d8(u32 param_1);
void FUN_801949ec(u16 *param_1,int param_2);
double FUN_80194a70(int param_1,u8 param_2);
f32 objFn_801948c0(u8 *obj,u8 coord);
void FUN_80194b10(u32 param_1,u32 param_2,int param_3);
void fn_80194964(int obj,int state,int block);
void fn_80194C40(u32 def,int state,int block);
u8 wallanimator_modelMtxFn(int *obj);
u8 wallanimator_func0B(int *obj);
int wallanimator_getExtraSize(void);
void wallanimator_free(int obj);
void wallanimator_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void wallanimator_update(int obj);
void wallanimator_init(s16 *obj,s16 *desc);
int xyzanimator_getExtraSize(void);
void xyzanimator_free(int obj,int param_2);

#endif /* MAIN_DLL_MMP_MMP_LEVELCONTROL_H_ */
