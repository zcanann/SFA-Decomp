#ifndef MAIN_DLL_MAGICPLANT_H_
#define MAIN_DLL_MAGICPLANT_H_

#include "ghidra_import.h"
#include "main/game_object.h"

extern u8 gMagicPlantSeqEntryTable[8];

void vambat_updateIdle(GameObject* obj, int state);
void vambat_updateEngaged(GameObject* obj, int state);
void fn_8015355C(GameObject* obj, int state);

void FUN_80153738(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,u32 *param_10);
void FUN_80153be0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10);
void FUN_80153db4(u32 param_1,int param_2,u32 param_3,int param_4,u32 param_5,
                 int param_6);
void FUN_80153e5c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9,int param_10);
void FUN_801544a4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10);

#endif /* MAIN_DLL_MAGICPLANT_H_ */
