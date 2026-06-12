#ifndef MAIN_DLL_MTXBUILDARG_STRUCT_H_
#define MAIN_DLL_MTXBUILDARG_STRUCT_H_

#include "types.h"

typedef struct MtxBuildArg
{
    s16 rx;
    s16 ry;
    s16 rz;
    u8 pad6[2];
    f32 w;
    f32 a;
    f32 b;
    f32 c;
} MtxBuildArg;

#endif
