#ifndef MAIN_DLL_PROJSWITCH_H_
#define MAIN_DLL_PROJSWITCH_H_

#include "ghidra_import.h"

void enemy_free(int obj, int flag);
void FUN_8014d3d0(short *param_1,u32 param_2,u32 param_3,short param_4);
void FUN_8014d4c8(double param_1,double param_2,double param_3,u64 param_4,u64 param_5
                 ,u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
                 u32 param_11,u32 param_12,u32 param_13,u32 param_14,
                 u32 param_15,u32 param_16);
void FUN_8014d59c(int param_1,u32 *param_2);
void FUN_8014d600(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8014d7b8(u32 param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8014d924(int param_1);
void enemy_init(int obj, u8 *setup, int flag);
void FUN_8014d9e8(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,int param_10,int param_11);

#endif /* MAIN_DLL_PROJSWITCH_H_ */
