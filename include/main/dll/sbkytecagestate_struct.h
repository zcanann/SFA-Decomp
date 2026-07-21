#ifndef MAIN_DLL_SBKYTECAGESTATE_STRUCT_H_
#define MAIN_DLL_SBKYTECAGESTATE_STRUCT_H_

#include "main/game_object.h"

typedef struct SBKyteCageState
{
    GameObject* kyte; /* attached objType-0x121 child */
    u8 seqLatch;
    u8 releaseStage; /* first activation runs trigger 1; later activations run trigger 2 */
    u8 pad06[2];
} SBKyteCageState;

#endif
