#ifndef MAIN_DLL_DLL_0104_SMALLBASKET_H_
#define MAIN_DLL_DLL_0104_SMALLBASKET_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

void FUN_801816f8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int SmallBasket_getExtraSize(void);
void objThrowFn_80182504(GameObject* obj);

extern ObjectDescriptor gSmallBasketObjDescriptor;

#endif /* MAIN_DLL_DLL_0104_SMALLBASKET_H_ */
