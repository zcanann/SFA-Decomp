#ifndef MAIN_DLL_DLL_13B_H_
#define MAIN_DLL_DLL_13B_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

int kaldachompme_getExtraSize(void);
int kaldachompme_getObjectTypeId(void);
void kaldachompme_free(void);
void kaldachompme_render(u32 param_1,u32 param_2,u32 param_3,u32 param_4,
                         u32 param_5,s8 renderFlag);
void kaldachompme_hitDetect(void);
void kaldachompme_update(int obj);
void kaldachompme_init(int obj,int params);
void kaldachompme_release(void);
void kaldachompme_initialise(void);
void kaldachompme_setLinkedMouthMode(u8 *obj, u8 mode);
void FUN_801695e8(int param_1,u8 param_2);
void FUN_8016980c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80169834(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_80169960(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_80169a44(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_80169c04(int param_1);
void kaldachompspit_render(void *obj, int p2, int p3, int p4, int p5, s8 visible);

extern ObjectDescriptor gKaldaChompMeObjDescriptor;

#endif /* MAIN_DLL_DLL_13B_H_ */
