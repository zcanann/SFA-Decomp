#ifndef MAIN_DLL_DLL_00E6_RESTARTMARKER_H_
#define MAIN_DLL_DLL_00E6_RESTARTMARKER_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gReStartMarkerObjDescriptor;

void restartmarker_init(GameObject* obj, s8* placement);

#endif
