#ifndef MAIN_DLL_CF_WINDLIFT_H_
#define MAIN_DLL_CF_WINDLIFT_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

void scarab_update(int obj);
void FUN_80184a54(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void fn_80185868(int obj, f32 arg);
void fn_80185A24(int obj, int p2, int p3, int p4, int p5, s8 renderState);
void fn_80185B74(int obj);

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
int portalspelldoor_getObjectTypeId(void);
void portalspelldoor_free(void);
void portalspelldoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void portalspelldoor_hitDetect(void);
void portalspelldoor_update(int obj);
void portalspelldoor_init(u8* obj, u8* data);
void portalspelldoor_release(void);
void portalspelldoor_initialise(void);

void LanternFireFly_modelMtxFn(u8* obj, f32 a, f32 b, f32 c);
void LanternFireFly_func0B(int obj);
void LanternFireFly_setScale(u8* obj, f32* vec);
void fn_801868D0(int obj);
void fn_801869DC(int obj);

#endif /* MAIN_DLL_CF_WINDLIFT_H_ */
