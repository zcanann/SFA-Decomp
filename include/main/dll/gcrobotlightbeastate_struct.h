#ifndef MAIN_DLL_GCROBOTLIGHTBEASTATE_STRUCT_H_
#define MAIN_DLL_GCROBOTLIGHTBEASTATE_STRUCT_H_

#include "types.h"

typedef struct GcRobotLightBeaState
{
    void* light; /* modelLightStruct point light */
    int unk4;
    u8 hitFlags; /* 0x80 = player caught in the beam */
    u8 pad9[3];
} GcRobotLightBeaState;

#endif
