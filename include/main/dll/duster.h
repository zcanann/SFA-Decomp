#ifndef MAIN_DLL_DUSTER_H_
#define MAIN_DLL_DUSTER_H_

#include "ghidra_import.h"
#include "main/game_object.h"

void rachnopUpdateApproach(int* obj, int state);
void rachnopUpdateAttack(int* obj, int state);
void rachnopUpdateIdle(int* obj, int state);
void spittingEbaUpdateIdle(GameObject* obj, int state);
void spittingEbaUpdateEngaged(u32 obj, int state);

void FUN_80155b6c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int *param_9,int param_10);
void FUN_80155cac(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int *param_9,int param_10);
void FUN_80155e00(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int *param_9,int param_10);
void rachnopInit(u32 param_1,int param_2);
void spittingEbaSpawnPollen(u32 param_9,int param_10);
void spittingEbaUpdateTimeOfDay(int param_9,int param_10);
void FUN_8015666c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_80156978(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10);
void spittingEbaInit(u32 param_1,int param_2);
void FUN_80156eb8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_80157220(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,u32 *param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void wbInit(u32 param_1,int param_2);
void FUN_801579f4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10);

#endif /* MAIN_DLL_DUSTER_H_ */
