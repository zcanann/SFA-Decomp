#ifndef MAIN_DLL_SEQOBJECTSTATE_STRUCT_H_
#define MAIN_DLL_SEQOBJECTSTATE_STRUCT_H_

#include "types.h"

typedef struct SeqObjectState
{
    u8 flags;
    s8 triggerBitState;
    u8 pad02;
} SeqObjectState;

#endif
