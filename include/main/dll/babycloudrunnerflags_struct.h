#ifndef MAIN_DLL_BABYCLOUDRUNNERFLAGS_STRUCT_H_
#define MAIN_DLL_BABYCLOUDRUNNERFLAGS_STRUCT_H_

#include "types.h"

typedef struct BabyCloudrunnerFlags
{
    u8 resetLatch : 1;
    u8 flags : 7;
} BabyCloudrunnerFlags;

#endif
