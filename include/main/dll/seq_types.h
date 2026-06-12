#ifndef MAIN_DLL_SEQ_TYPES_H_
#define MAIN_DLL_SEQ_TYPES_H_

#include "types.h"

typedef struct SeqObjectState
{
    u8 flags;
    s8 triggerBitState;
    u8 pad02;
} SeqObjectState;

typedef struct SeqObj2State
{
    u8 flags;
} SeqObj2State;

#endif
