#ifndef MAIN_DLL_MMSHRINE_ECSH_SHRINE_STATE_H_
#define MAIN_DLL_MMSHRINE_ECSH_SHRINE_STATE_H_

#include "global.h"

typedef struct EcshShrineState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 cooldownTimer;
    u8 padC[0x18 - 0xC];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 timer;
    s16 animState;
    s16 matchFlag;
    u8 pad28[0x2E - 0x28];
    u8 targetSlot;
    u8 unk2F;
    u8 unk30;
    u8 pad31[0x32 - 0x31];
    u8 unk32;
    u8 pad33[0x34 - 0x33];
    s32 gameBitLatchState;
} EcshShrineState;

#endif
