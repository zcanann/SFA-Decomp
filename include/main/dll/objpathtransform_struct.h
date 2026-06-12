#ifndef MAIN_DLL_OBJPATHTRANSFORM_STRUCT_H_
#define MAIN_DLL_OBJPATHTRANSFORM_STRUCT_H_

#include "types.h"

typedef struct ObjPathTransform
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u8 pad06[2];
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjPathTransform;

#endif
