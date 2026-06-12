#ifndef MAIN_DLL_CFPRISONUNCLESTATE_STRUCT_H_
#define MAIN_DLL_CFPRISONUNCLESTATE_STRUCT_H_

#include "types.h"

typedef struct CfPrisonUncleState
{
    int target; /* keyed type-0x3d object */
    u8 lookBlock[0x30]; /* fn_8003ADC4 head-track block */
    u8 audioBlock[0x30]; /* objAudioFn block */
    int unk64;
    int unk68;
    u8 pad6C[4];
    s16 unk70;
    u8 pad72;
    s8 captured; /* GameBit 0x4d latch */
    s8 kicked; /* fn_8019FC84 one-shot */
    u8 pad75[0x33];
} CfPrisonUncleState;

#endif
