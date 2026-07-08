#ifndef MAIN_DLL_DLL1FBSETUP_STRUCT_H_
#define MAIN_DLL_DLL1FBSETUP_STRUCT_H_

#include "types.h"
#include "main/obj_placement.h"

typedef struct Dll1FBSetup
{
    ObjPlacement base;
    s8 yawByte;
    s8 baseMove;
    s16 triggerMode;
    s16 objectParam;
} Dll1FBSetup;

#endif
