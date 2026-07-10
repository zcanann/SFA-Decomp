#ifndef MAIN_DLL_CF_TREASURERELATED0177_H_
#define MAIN_DLL_CF_TREASURERELATED0177_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gCampFireObjDescriptor;
extern ObjectDescriptor gKT_TorchObjDescriptor;
extern ObjectDescriptor gCFCrateObjDescriptor;

void dll_127_update(int obj);
void FUN_8018cdb0(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9, u32 param_10, u32 param_11, u32 param_12, u32 param_13, u32 param_14,
                  u32 param_15, u32 param_16);
void FUN_8018cf58(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void dll_127_init(short* param_1, int param_2);
void FUN_8018d064(int param_1);
void FUN_8018d0b4(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_8018d110(void);
int CampFire_getExtraSize(void);
int CampFire_getObjectTypeId(void);
void CampFire_free(GameObject* obj);
void CampFire_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible);
int KT_Torch_getExtraSize(void);
int KT_Torch_getObjectTypeId(void);
void KT_Torch_free(void);
void KT_Torch_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void KT_Torch_hitDetect(void);
void KT_Torch_update(GameObject* obj);
void KT_Torch_release(void);
void KT_Torch_initialise(void);
int CFCrate_getExtraSize(void);
int CFCrate_getObjectTypeId(void);
void CFCrate_free(int obj);

#endif /* MAIN_DLL_CF_TREASURERELATED0177_H_ */
