#ifndef MAIN_DLL_DLL_10A_H_
#define MAIN_DLL_DLL_10A_H_

#include "ghidra_import.h"
#include "main/dll/baddie_state.h"
#include "main/game_object.h"

void baddieSpawnWaterRipple(GameObject* obj, BaddieState* state);
void pinPon_updateIdle(GameObject* obj, int state);

void FUN_80154108(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10,u32 param_11,int param_12,u32 param_13,
                 u32 param_14,u32 param_15,u32 param_16);
void FUN_80154290(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9,u32 *param_10);
void FUN_80154724(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9,int param_10);

#endif /* MAIN_DLL_DLL_10A_H_ */
