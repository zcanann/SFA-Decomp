#ifndef MAIN_DLL_DLL_1CA_H_
#define MAIN_DLL_DLL_1CA_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void dll_197_init(int obj, int data);
void FUN_801caa30(u16 *param_1,int param_2);
u32 FUN_801cab60(u32 param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801caca0(void);
void FUN_801cacfc(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_801caeac(int param_1);
void FUN_801caeb0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,ObjAnimUpdateState *animUpdate,u32 param_12,
                 u32 param_13,int param_14,u32 param_15,u32 param_16);
void dll_197_release(void);
void dll_197_initialise(void);
int dll_199_getExtraSize(void);
int dll_199_getObjectTypeId(void);
void dll_199_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_199_hitDetect(void);
int NWSH_levcon_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);

#endif /* MAIN_DLL_DLL_1CA_H_ */
