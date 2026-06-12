#ifndef MAIN_DLL_DLL1FBSTATE_STRUCT_H_
#define MAIN_DLL_DLL1FBSTATE_STRUCT_H_

#include "types.h"

typedef struct Dll1FBState
{
    u8 pad00[4];
    s16 baseMove;
    s16 triggerMode;
    u8 pad08;
    u8 hideModel;
    u8 pad0A[2];
} Dll1FBState;

#endif
