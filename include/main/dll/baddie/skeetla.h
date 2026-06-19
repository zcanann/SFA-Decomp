#ifndef MAIN_DLL_BADDIE_SKEETLA_H_
#define MAIN_DLL_BADDIE_SKEETLA_H_

#include "ghidra_import.h"
#include "main/dll/curve_walker.h"

void trickyUpdateCollisionAndPathState(u8 *obj);
int trickyAdvanceRouteTargetAhead(int obj, RomCurveWalker *route, f32 speed);
u32 FUN_80139800(double param_1,int param_2,float *param_3);
int FUN_80139910(u16 *param_1,u16 param_2);
void FUN_80139a48(void);
u32 FUN_80139a4c(double param_1,int param_2,int param_3,u32 param_4);
int fn_8013A874(u32 param_1,u32 param_2,u32 param_3,u32 param_4);
int FUN_80139ce8(int param_1,int param_2,int param_3);
void FUN_80139e1c(u32 param_1,u32 param_2,int param_3,int param_4);
void fn_8013AD50(int param_1,int param_2,u8 param_3);
void FUN_8013a144(u32 param_1,u32 param_2,u16 param_3,u32 *param_4);
void FUN_8013a408(u16 *param_1);
void FUN_8013a5b0(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 float *param_5,float *param_6);
void FUN_8013a804(u32 param_1,u32 param_2,float *param_3);

#endif /* MAIN_DLL_BADDIE_SKEETLA_H_ */
