#ifndef MAIN_DLL_DR_HIGHTOP_H_
#define MAIN_DLL_DR_HIGHTOP_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

u32 FUN_801993b0(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                 u64 param_8, u32 param_9, u32 param_10, u32 param_11, int param_12, int param_13, u32 param_14,
                 u32 param_15, u32 param_16);
void FUN_8019ada4(int param_1);
void FUN_8019ae30(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, u32 param_9, u32 param_10, float* param_11, u32 param_12, int param_13, u32 param_14,
                  u32 param_15, u32 param_16);
void FUN_8019b6ac(u16* param_1, short* param_2);
void FUN_8019b844(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_8019b86c(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, u32 param_9);
void FUN_8019bc2c(int param_1);

int Trigger_getExtraSize(void);
int Trigger_getObjectTypeId(void);
void Trigger_free(GameObject* obj);
void Trigger_render(void);
void Trigger_hitDetect(GameObject* obj);
void Trigger_update(void);
void Trigger_init(u8* obj, u8* params);
void Trigger_release(void);
void Trigger_initialise(void);

extern ObjectDescriptor gTriggerObjDescriptor;

int CloudPrisonControl_getExtraSize(void);
int CloudPrisonControl_getObjectTypeId(void);
void CloudPrisonControl_free(void);
void CloudPrisonControl_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void CloudPrisonControl_hitDetect(void);
void CloudPrisonControl_update(GameObject* obj);
void CloudPrisonControl_init(int obj);
void CloudPrisonControl_release(void);
void CloudPrisonControl_initialise(void);

extern ObjectDescriptor gCloudPrisonControlObjDescriptor;

#endif /* MAIN_DLL_DR_HIGHTOP_H_ */
