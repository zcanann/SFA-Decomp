#ifndef MAIN_DLL_MMSHRINE_ANIMOBJ1C0_H_
#define MAIN_DLL_MMSHRINE_ANIMOBJ1C0_H_

#include "ghidra_import.h"

void FUN_801c5990(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_801c5c2c(int param_1);
struct MmShrineAnimObj;
void fn_801C5990(struct MmShrineAnimObj *obj);
int fn_801C5CE4(void *obj, int unused, void *eventList);
void ecsh_shrine_getPhaseAndSpiritCup(int *outRot, u8 *outIndex);
void ecsh_shrine_checkCupPick(u8 index);
void ecsh_shrine_setCupPos(u8 index, f32 a, f32 b);

#endif /* MAIN_DLL_MMSHRINE_ANIMOBJ1C0_H_ */
