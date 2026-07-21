#ifndef MAIN_DLL_DLL_00EA_SIDELOAD_H_
#define MAIN_DLL_DLL_00EA_SIDELOAD_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct SideloadPlacement
{
    ObjPlacement base;
    s16 armGameBit; /* 0x18: arming game bit */
    u8 rotX;        /* 0x1A: child rotation, shifted into anim.rotX */
    u8 pad1B;
} SideloadPlacement;

STATIC_ASSERT(offsetof(SideloadPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(SideloadPlacement, armGameBit) == 0x18);
STATIC_ASSERT(offsetof(SideloadPlacement, rotX) == 0x1A);
STATIC_ASSERT(sizeof(SideloadPlacement) == 0x1C);

void sideload_update(GameObject* self);

extern ObjectDescriptor gSideloadObjDescriptor;

#endif /* MAIN_DLL_DLL_00EA_SIDELOAD_H_ */
