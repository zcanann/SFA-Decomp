#ifndef MAIN_DLL_BIT80_STRUCT_H_
#define MAIN_DLL_BIT80_STRUCT_H_

#include "types.h"

typedef struct
{
    u8 top : 1;
    u8 rest : 7;
} Bit80;

#endif
