#ifndef MAIN_DLL_AUTOTRANSPORTER_H_
#define MAIN_DLL_AUTOTRANSPORTER_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDoorF4ObjDescriptor;
extern ObjectDescriptor gSidekickBallObjDescriptor;

void FUN_80178338(undefined4 param_1);
void FUN_80178370(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801784ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_80178560(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801797bc(int param_1);
void FUN_80179820(int param_1);
void FUN_80179848(undefined2 *param_1);
void FUN_801799bc(undefined2 *param_1,int param_2);
uint FUN_801799c0(int param_1);

int doorf4_getExtraSize(void);
int doorf4_func08(void);
void doorf4_free(int obj);
void doorf4_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void doorf4_hitDetect(void);
void doorf4_update(void);
void doorf4_init(void);
void doorf4_release(void);
void doorf4_initialise(void);

int sidekickball_getExtraSize(void);
void sidekickball_free(int obj);
void sidekickball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#endif /* MAIN_DLL_AUTOTRANSPORTER_H_ */
