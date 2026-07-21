#ifndef MAIN_DLL_DLL_01F6_FLAG_H_
#define MAIN_DLL_DLL_01F6_FLAG_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct FlagPlacement
{
    ObjPlacement base;
    s8 rotX;
} FlagPlacement;

STATIC_ASSERT(offsetof(FlagPlacement, rotX) == 0x18);

int Flag_getExtraSize(void);
int Flag_getObjectTypeId(void);
void Flag_free(void);
void Flag_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void Flag_hitDetect(void);
void Flag_update(GameObject* obj);
void Flag_init(GameObject* obj, FlagPlacement* placement);
void Flag_release(void);
void Flag_initialise(void);

extern ObjectDescriptor gFlagObjDescriptor;

#endif /* MAIN_DLL_DLL_01F6_FLAG_H_ */
