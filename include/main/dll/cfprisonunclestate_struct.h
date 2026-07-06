#ifndef MAIN_DLL_CFPRISONUNCLESTATE_STRUCT_H_
#define MAIN_DLL_CFPRISONUNCLESTATE_STRUCT_H_

#include "types.h"

typedef struct CfPrisonUncleState
{
    int target; /* class-0x3D companion object (carries his escape path) */
    u8 lookBlock[0x30]; /* fn_8003ADC4 head-track block */
    u8 audioBlock[0x30]; /* objAudioFn block */
    int unk64;
    int unk68;
    u8 pad6C[4];
    s16 unk70;
    u8 pad72;
    s8 released; /* GameBit 0x4D latch: his cage has been opened */
    s8 magicGranted; /* one-shot thank-you magic in CFPrisonUncle_SeqFn */
    u8 pad75[0x33];
} CfPrisonUncleState;

#endif
