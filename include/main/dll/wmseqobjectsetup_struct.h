#ifndef MAIN_DLL_WMSEQOBJECTSETUP_STRUCT_H_
#define MAIN_DLL_WMSEQOBJECTSETUP_STRUCT_H_

#include "types.h"
#include "main/obj_placement.h"

typedef struct WMSeqObjectSetup
{
    ObjPlacement base;
    s8 yawByte;
    s8 setupType;
} WMSeqObjectSetup;

#endif
