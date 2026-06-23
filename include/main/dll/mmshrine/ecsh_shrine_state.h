#ifndef MAIN_DLL_MMSHRINE_ECSH_SHRINE_STATE_H_
#define MAIN_DLL_MMSHRINE_ECSH_SHRINE_STATE_H_

#include "global.h"

typedef struct EcshShrineState
{
    u8 pad0[0x4 - 0x0];
    f32 animTimer;
    f32 cooldownTimer;
    u8 padC[0x18 - 0xC];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 shuffleCount; /* 0x22: remaining shuffle iterations this round (5/7/9 for rounds 1/2/3) */
    s16 animState;
    s16 matchFlag; /* 0x26: pick result: 1 = correct cup, 0 = wrong, -1 = pending */
    u8 pad28[0x2E - 0x28];
    u8 spiritCup; /* 0x2E: which cup (0-5) the Krazoa Spirit is hidden in (randomGetRange(0,5)) */
    u8 testPhase; /* 0x2F: outer state machine phase (see ecsh_shrine_update) */
    u8 transitionReady; /* 0x30: set when the intro screen transition has completed */
    u8 pad31[0x32 - 0x31];
    u8 introTextLatch; /* 0x32: latches GAMEBIT_K1_SHRINE_INTRO_TEXT_TRIGGER (0x58b); once set, the intro dialogue has been kicked off and won't replay */
    u8 pad33[0x34 - 0x33];
    s32 gameBitLatchState;
} EcshShrineState;

#endif
