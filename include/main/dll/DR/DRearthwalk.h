#ifndef MAIN_DLL_DR_DREARTHWALK_H_
#define MAIN_DLL_DR_DREARTHWALK_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void sh_staff_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
int sh_staff_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void FUN_801d9cc4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801da33c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,ObjAnimUpdateState *animUpdate);
void FUN_801da5d4(int param_1,u8 *param_2,int param_3);
void FUN_801da724(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_801da728(int param_1);
void FUN_801da774(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
u32 FUN_801da7f8(int param_1);
void FUN_801da868(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);

#endif /* MAIN_DLL_DR_DREARTHWALK_H_ */
