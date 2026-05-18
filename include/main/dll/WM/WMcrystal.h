#ifndef MAIN_DLL_WM_WMCRYSTAL_H_
#define MAIN_DLL_WM_WMCRYSTAL_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void sc_totempuzzle_update(void);
void FUN_801dd6b8(int param_1);
void FUN_801dd6e0(undefined2 *param_1);
void FUN_801dd6e4(undefined2 *param_1,int param_2);
void sc_totembond_spawnGameBitOrbs(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
undefined4 sc_totempuzzle_processAnimEvents(int param_1,undefined4 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801ddb0c(void);
void FUN_801ddb3c(int param_1);

#endif /* MAIN_DLL_WM_WMCRYSTAL_H_ */
