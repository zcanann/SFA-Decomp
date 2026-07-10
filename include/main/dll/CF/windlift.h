#ifndef MAIN_DLL_CF_WINDLIFT_H_
#define MAIN_DLL_CF_WINDLIFT_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"

void Scarab_update(int obj);
void FUN_80184a54(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8);
void fn_80185868(GameObject* obj, f32 arg);
void dll_107_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 renderState);
void dll_107_update(GameObject* obj);

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

int PortalSpellDoor_getExtraSize(void);
int PortalSpellDoor_getObjectTypeId(void);
void PortalSpellDoor_free(void);
void PortalSpellDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void PortalSpellDoor_hitDetect(void);
void PortalSpellDoor_update(GameObject* obj);
void PortalSpellDoor_init(u8* obj, u8* data);
void PortalSpellDoor_release(void);
void PortalSpellDoor_initialise(void);

void LanternFireFly_modelMtxFn(u8* obj, f32 a, f32 b, f32 c);
void LanternFireFly_func0B(GameObject* obj);
void LanternFireFly_setScale(u8* obj, f32* vec);
void fn_801868D0(GameObject* obj);
void fn_801869DC(GameObject* obj);

#endif /* MAIN_DLL_CF_WINDLIFT_H_ */
