#ifndef MAIN_DLL_STAFFFLAGS_STRUCT_H_
#define MAIN_DLL_STAFFFLAGS_STRUCT_H_

#include "types.h"

typedef struct
{
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1;
    u8 b4 : 1;
    u8 rest : 4;
} StaffFlags;

#endif
