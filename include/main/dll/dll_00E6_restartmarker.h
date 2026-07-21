#ifndef MAIN_DLL_DLL_00E6_RESTARTMARKER_H_
#define MAIN_DLL_DLL_00E6_RESTARTMARKER_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct RestartMarkerPlacement
{
    ObjPlacement base;
    u8 rotXByte;
} RestartMarkerPlacement;

STATIC_ASSERT(offsetof(RestartMarkerPlacement, rotXByte) == 0x18);
STATIC_ASSERT(sizeof(RestartMarkerPlacement) == 0x1c);

extern ObjectDescriptor gReStartMarkerObjDescriptor;

void restartmarker_init(GameObject* obj, RestartMarkerPlacement* placement);

#endif /* MAIN_DLL_DLL_00E6_RESTARTMARKER_H_ */
