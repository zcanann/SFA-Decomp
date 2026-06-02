#ifndef MAIN_DLL_CF_CFCRYSTAL_H_
#define MAIN_DLL_CF_CFCRYSTAL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gLanternFireFlyObjDescriptor;
extern ObjectDescriptor gFireFlyLanternObjDescriptor;
extern ObjectDescriptor gFlammableVineObjDescriptor;

int LanternFireFly_getExtraSize(void);
int LanternFireFly_func08(void);
void LanternFireFly_free(void);
void LanternFireFly_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void LanternFireFly_hitDetect(void);
void LanternFireFly_update(int obj);
void LanternFireFly_init(int obj, int def);
void LanternFireFly_release(void);
void LanternFireFly_initialise(void);
void LanternFireFly_setScale(void);
void LanternFireFly_func0B(undefined2 *param_1,int param_2);
u8 LanternFireFly_modelMtxFn(int *obj);

int FireFlyLantern_getExtraSize(void);
int FireFlyLantern_getObjectTypeId(void);
void FireFlyLantern_free(int obj);
void FireFlyLantern_render(void);
void FireFlyLantern_update(int obj);
void FireFlyLantern_init(int param_1,int param_2);
int fn_8018728C(int obj, int unused, int events);

int flammablevine_getExtraSize(void);
int flammablevine_getObjectTypeId(void);
void flammablevine_free(int obj);
void flammablevine_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void flammablevine_hitDetect(void);
void flammablevine_update(void);
void flammablevine_init(void);
void flammablevine_release(void);
void flammablevine_initialise(void);

#endif /* MAIN_DLL_CF_CFCRYSTAL_H_ */
