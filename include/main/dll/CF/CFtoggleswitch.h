#ifndef MAIN_DLL_CF_CFTOGGLESWITCH_H_
#define MAIN_DLL_CF_CFTOGGLESWITCH_H_

#include "ghidra_import.h"
#include "main/objanim_internal.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gMagicCaveBottomObjDescriptor;
extern ObjectDescriptor gMagicCaveTopObjDescriptor;
extern ObjectDescriptor gInfoTextObjDescriptor;
extern ObjectDescriptor gCCTestInfotObjDescriptor;
extern ObjectDescriptor gDeathGasObjDescriptor;

void MagicCaveBottom_update(int *obj);
void FUN_8018aee4(void);
void FUN_8018af08(int param_1);
void FUN_8018af28(int param_1);
void FUN_8018af74(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8018b220(u16 *param_1);
void FUN_8018b224(void);
void FUN_8018b258(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8018b5a0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_8018b6ac(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
int MagicCaveTop_getExtraSize(void);
int infotext_getExtraSize(void);
int CCTestInfot_getExtraSize(void);
int DeathGas_getExtraSize(void);
#endif /* MAIN_DLL_CF_CFTOGGLESWITCH_H_ */
