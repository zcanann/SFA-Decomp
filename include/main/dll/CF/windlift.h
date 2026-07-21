#ifndef MAIN_DLL_CF_WINDLIFT_H_
#define MAIN_DLL_CF_WINDLIFT_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"

void FUN_80184a54(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8);
typedef struct WindLift107Placement WindLift107Placement;

void windLift107_finishSpitBurst(GameObject* obj, f32 playerDistance);
int windLift107_getExtraSize(void);
int windLift107_getObjectTypeId(void);
void windLift107_free(GameObject* obj);
void windLift107_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 renderState);
void windLift107_hitDetect(void);
void windLift107_update(GameObject* obj);
void windLift107_init(GameObject* obj, WindLift107Placement* placement);
void windLift107_release(void);
void windLift107_initialise(void);

extern ObjectDescriptor gWindLift107ObjDescriptor;

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
