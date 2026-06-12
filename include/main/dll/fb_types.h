#ifndef MAIN_DLL_FB_TYPES_H_
#define MAIN_DLL_FB_TYPES_H_

#include "types.h"

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} FbWGPipe;

typedef struct
{
    int v[4];
} FbTexTbl;

#endif
