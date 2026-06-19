#ifndef MAIN_DLL_MMSHRINE_SHRINE_H_
#define MAIN_DLL_MMSHRINE_SHRINE_H_

#include "ghidra_import.h"

void mmsh_shrine_init(u16 *param_1,int param_2);
void mmsh_scales_free(int param_1,int param_2);
void FUN_801c5448(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9);
void FUN_801c591c(u16 *param_1,int param_2);
void FUN_801c5920(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_801c5a34(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801c5a5c(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);

#endif /* MAIN_DLL_MMSHRINE_SHRINE_H_ */
