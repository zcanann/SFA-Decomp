#ifndef MAIN_DLL_DF_PARTFX_H_
#define MAIN_DLL_DF_PARTFX_H_

#include "ghidra_import.h"
#include "main/checkpoint_route.h"
#include "main/game_object.h"

int Checkpoint_func07(GameObject *obj, CheckpointRouteState *state);
void FUN_800d7c90(double param_1,double param_2,double param_3,double param_4,double param_5,
                 int param_6,int param_7);
void FUN_800d84e0(u32 param_1,u32 param_2,int param_3,int param_4,u32 param_5,
                 int param_6);
void FUN_800d85f4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10,u32 param_11,u32 param_12,u32 param_13,
                 u32 param_14,u32 param_15,u32 param_16);

#endif /* MAIN_DLL_DF_PARTFX_H_ */
