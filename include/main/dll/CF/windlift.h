#ifndef MAIN_DLL_CF_WINDLIFT_H_
#define MAIN_DLL_CF_WINDLIFT_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"

void FUN_80184a54(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8);
void fn_80185868(GameObject* obj, f32 arg);
int dll_107_getExtraSize_ret_44(void);
int dll_107_getObjectTypeId(void);
void dll_107_free(int* obj);
void dll_107_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 renderState);
void dll_107_hitDetect_nop(void);
void dll_107_update(GameObject* obj);
void dll_107_init(int obj, int pArg);
void dll_107_release_nop(void);
void dll_107_initialise_nop(void);

extern ObjectDescriptor gPortalSpellDoorObjDescriptor;

int PortalSpellDoor_getExtraSize(void);
int PortalSpellDoor_getObjectTypeId(void);
void PortalSpellDoor_free(void);
void PortalSpellDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void PortalSpellDoor_hitDetect(void);
void PortalSpellDoor_update(GameObject* obj);
void PortalSpellDoor_init(GameObject* obj, u8* data);
void PortalSpellDoor_release(void);
void PortalSpellDoor_initialise(void);

#endif /* MAIN_DLL_CF_WINDLIFT_H_ */
