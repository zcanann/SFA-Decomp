#ifndef MAIN_DLL_SBKYTECAGESTATE_STRUCT_H_
#define MAIN_DLL_SBKYTECAGESTATE_STRUCT_H_

#include "types.h"

typedef struct SBKyteCageState
{
    void* kyte; /* attached objType-0x121 child */
    u8 seqLatch;
    u8 doorChoice; /* picks trigger 2 vs 1 on release */
    u8 pad06[2];
} SBKyteCageState;

#endif
