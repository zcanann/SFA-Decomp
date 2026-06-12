#ifndef MAIN_DLL_WATERFXCFG_STRUCT_H_
#define MAIN_DLL_WATERFXCFG_STRUCT_H_

#include "types.h"

typedef struct WaterfxCfg
{
    s16 x;
    s16 y;
    s16 z;
    u8 pad6[2];
    f32 f8;
    f32 fc;
    f32 f10;
    f32 f14;
} WaterfxCfg;

#endif
