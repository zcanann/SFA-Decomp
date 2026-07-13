#ifndef MAIN_DLL_DLL_00E5_SHIELD_API_H_
#define MAIN_DLL_DLL_00E5_SHIELD_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gShieldObjDescriptor;

GameObject* fn_801702D4(GameObject* obj, f32 rootMotionScale);
void Shield_free(GameObject* obj);
int Shield_getExtraSize(void);
int Shield_getObjectTypeId(void);
void Shield_hitDetect(void);
void Shield_init(int* obj, void* initData);
void Shield_initialise(void);
void Shield_release(void);
void Shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void Shield_update(int* obj);
void staffFn_80170380(GameObject* obj, int command);

#endif /* MAIN_DLL_DLL_00E5_SHIELD_API_H_ */
