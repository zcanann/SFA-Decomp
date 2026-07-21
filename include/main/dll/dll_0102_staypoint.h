#ifndef MAIN_DLL_DLL_0102_STAYPOINT_H_
#define MAIN_DLL_DLL_0102_STAYPOINT_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct StayPointPlacement
{
    ObjPlacement base;
    u8 pad18[6];
    s16 activeGameBit;
    s16 requiredGameBit;
} StayPointPlacement;

STATIC_ASSERT(offsetof(StayPointPlacement, activeGameBit) == 0x1e);
STATIC_ASSERT(offsetof(StayPointPlacement, requiredGameBit) == 0x20);
STATIC_ASSERT(sizeof(StayPointPlacement) == 0x24);

void StayPoint_update(GameObject* obj);
void StayPoint_init(GameObject* obj);

extern ObjectDescriptor gStayPointObjDescriptor;

#endif /* MAIN_DLL_DLL_0102_STAYPOINT_H_ */
