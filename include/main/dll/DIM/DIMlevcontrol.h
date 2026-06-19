#ifndef MAIN_DLL_DIM_DIMLEVCONTROL_H_
#define MAIN_DLL_DIM_DIMLEVCONTROL_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void FUN_801b2550(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,ObjAnimUpdateState *animUpdate);
void FUN_801b2bd8(int param_1);
void FUN_801b2c40(u16 *param_1);
void FUN_801b2ccc(double param_1,double param_2,double param_3,double param_4,u64 param_5,
                 u64 param_6,u64 param_7,u64 param_8,short *param_9);
void dimlavasmash_render(int *obj, int p2, int p3, int p4, int p5, s8 visible);
int dimlavasmash_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);

#endif /* MAIN_DLL_DIM_DIMLEVCONTROL_H_ */
