#ifndef MAIN_DLL_DLL_00EA_SIDELOAD_H_
#define MAIN_DLL_DLL_00EA_SIDELOAD_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct SideloadPlacement
{
    ObjPlacement base;
    s16 armGameBit; /* 0x18: arming game bit */
    u8 yawByte;     /* 0x1A: spawn yaw, shifted << 8 into the child's s16 rotation */
    u8 pad1B;
} SideloadPlacement;

STATIC_ASSERT(offsetof(SideloadPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(SideloadPlacement, armGameBit) == 0x18);
STATIC_ASSERT(offsetof(SideloadPlacement, yawByte) == 0x1A);
STATIC_ASSERT(sizeof(SideloadPlacement) == 0x1C);

void sideload_update(GameObject* self);

#endif /* MAIN_DLL_DLL_00EA_SIDELOAD_H_ */
