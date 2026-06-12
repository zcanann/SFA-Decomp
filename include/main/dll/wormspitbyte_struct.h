#ifndef MAIN_DLL_WORMSPITBYTE_STRUCT_H_
#define MAIN_DLL_WORMSPITBYTE_STRUCT_H_

#include "types.h"

typedef struct
{
    u8 _p0 : 1;
    u8 spitLatch : 1;
    u8 _p1 : 6;
} WormSpitByte;

#endif
