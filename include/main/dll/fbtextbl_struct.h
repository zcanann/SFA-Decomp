#ifndef MAIN_DLL_FBTEXTBL_STRUCT_H_
#define MAIN_DLL_FBTEXTBL_STRUCT_H_

#include "types.h"

typedef struct
{
    int v[4];
} FbTexTbl;

STATIC_ASSERT(sizeof(FbTexTbl) == 0x10);

#endif
