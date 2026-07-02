#ifndef MAIN_DLL_AUTOTRANSPORTER_H_
#define MAIN_DLL_AUTOTRANSPORTER_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDoorF4ObjDescriptor;
extern ObjectDescriptor gSidekickBallObjDescriptor;

int doorf4_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void FUN_80178370(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_801784ac(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_80178560(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,ObjAnimUpdateState *animUpdate,
                 u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_801797bc(int param_1);
void FUN_80179820(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80179848(u16 *param_1);
void FUN_801799bc(u16 *param_1,int param_2);
u32 FUN_801799c0(int param_1);

int doorf4_getExtraSize(void);
int doorf4_getObjectTypeId(void);
void doorf4_free(int obj);
void doorf4_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void doorf4_hitDetect(void);
void doorf4_update(int *obj);
void doorf4_init(int *obj, int *params);
void doorf4_release(void);
void doorf4_initialise(void);

int sidekickball_getExtraSize(void);
void sidekickball_free(int obj);
void sidekickball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#endif /* MAIN_DLL_AUTOTRANSPORTER_H_ */
