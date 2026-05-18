#ifndef MAIN_DLL_CF_WINDLIFT_H_
#define MAIN_DLL_CF_WINDLIFT_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

void scarab_update(int param_1);
void FUN_80184a54(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_801858a8(int param_1,int param_2);
void FUN_80185a48(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_80185c48(void);
void FUN_80185c9c(void);
void FUN_80185dc4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_8018671c(undefined2 *param_1,int param_2);
void FUN_80186720(int param_1);
void FUN_80186748(int param_1);

extern ObjectDescriptor gDummy108ObjDescriptor;
extern ObjectDescriptor gPortalSpellDoorObjDescriptor;

int Dummy108_getExtraSize(void);
int Dummy108_func08_ret_0(void);
void Dummy108_free(void);
void Dummy108_render(void);
void Dummy108_hitDetect(void);
void Dummy108_update(void);
void Dummy108_init(void);
void Dummy108_release(void);
void Dummy108_initialise(void);

int portalspelldoor_getExtraSize(void);
int portalspelldoor_func08(void);
void portalspelldoor_free(void);
void portalspelldoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void portalspelldoor_hitDetect(void);
void portalspelldoor_update(void);
void portalspelldoor_init(void);
void portalspelldoor_release(void);
void portalspelldoor_initialise(void);

#endif /* MAIN_DLL_CF_WINDLIFT_H_ */
