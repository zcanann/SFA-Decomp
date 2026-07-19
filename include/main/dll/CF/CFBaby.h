#ifndef MAIN_DLL_CF_CFBABY_H_
#define MAIN_DLL_CF_CFBABY_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gLanternFireFlyObjDescriptor;
extern ObjectDescriptor gFireFlyLanternObjDescriptor;
extern ObjectDescriptor gFlammableVineObjDescriptor;

void FireFlyLantern_init(GameObject* param_1, int param_2);
GameObject* FireFlyLantern_spawnFireFly(int* obj);
int FireFlyLantern_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int FUN_80187664(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                 u64 param_8, int param_9);
void FUN_8018795c(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9);
void FUN_80187b14(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9, int param_10);
void FUN_801880e0(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, u32 param_9);
void InfoPoint_hitDetect(void);
void FUN_80188864(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, short* param_9, int param_10, u32 param_11, u32 param_12, u32 param_13, u32 param_14,
                  u32 param_15, u32 param_16);
void FUN_80188f94(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9);
u32 FUN_80189054(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                 u64 param_8, int param_9, u32 param_10, ObjAnimUpdateState* animUpdate, int param_12, u32 param_13,
                 u32 param_14, u32 param_15, u32 param_16);
void FUN_80189a90(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9);
int Landed_Arwing_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int InfoPoint_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_CF_CFBABY_H_ */
