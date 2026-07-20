#ifndef MAIN_DLL_DIM_DLL_01CB_DIMWOODDOOR2_H_
#define MAIN_DLL_DIM_DLL_01CB_DIMWOODDOOR2_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/dimwooddoor2placement_struct.h"

int dimwooddoor2_getExtraSize(void);
int dimwooddoor2_getObjectTypeId(void);
void dimwooddoor2_free(void);
void dimwooddoor2_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dimwooddoor2_hitDetect(void);
void dimwooddoor2_update(GameObject* obj);
void dimwooddoor2_init(GameObject* obj, Dimwooddoor2Placement* placement);
void dimwooddoor2_release(void);
void dimwooddoor2_initialise(void);

extern ObjectDescriptor gDIMWoodDoor2ObjDescriptor;

#endif
