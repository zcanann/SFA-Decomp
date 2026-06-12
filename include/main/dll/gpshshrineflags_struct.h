#ifndef MAIN_DLL_GPSHSHRINEFLAGS_STRUCT_H_
#define MAIN_DLL_GPSHSHRINEFLAGS_STRUCT_H_

#include "types.h"

typedef struct
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} GpshShrineFlags;

#endif
