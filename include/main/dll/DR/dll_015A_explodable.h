#ifndef MAIN_DLL_DR_GASVENTCONTROL_H_
#define MAIN_DLL_DR_GASVENTCONTROL_H_

#include "ghidra_import.h"

void blasted_init(int param_1,int param_2);
u32 FUN_801a2cb8(int param_1,u32 param_2);
void FUN_801a2dc4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a2dfc(void);
void FUN_801a3144(u16 *param_1,int param_2);
u32
FUN_801a32d4(u64 param_1,u64 param_2,double param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,int param_9,
            u16 param_10,int param_11,u8 param_12,u32 param_13,
            u32 param_14,u32 param_15,u32 param_16);
void FUN_801a35f4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11,int param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_801a35f8(int param_1,int param_2,int param_3);

#endif /* MAIN_DLL_DR_GASVENTCONTROL_H_ */
