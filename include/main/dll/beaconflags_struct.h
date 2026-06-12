#ifndef MAIN_DLL_BEACONFLAGS_STRUCT_H_
#define MAIN_DLL_BEACONFLAGS_STRUCT_H_

#include "types.h"

typedef struct
{
    u8 looping : 1;
    u8 rest : 7;
} BeaconFlags;

#endif
