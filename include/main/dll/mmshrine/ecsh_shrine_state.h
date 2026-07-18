#ifndef MAIN_DLL_MMSHRINE_ECSH_SHRINE_STATE_H_
#define MAIN_DLL_MMSHRINE_ECSH_SHRINE_STATE_H_

#include "global.h"

typedef struct EcshShrineState
{
    u8 pad0[0x4 - 0x0];
    f32 animTimer;
    f32 cooldownTimer;
    f32 guessTimer;          /* 0xC: countdown to force a fail if no cup is picked (set to 600 when shuffles finish) */
    f32 voiceTimer;          /* 0x10: idle spirit-voice replay countdown (phase 0) */
    f32 shuffleSfxThreshold; /* 0x14: randomised (40-60) threshold vs animTimer that gates the mid-shuffle sfx */
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 scale; /* 0x20: reported out via ecsh_shrine_setScale */
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

STATIC_ASSERT(offsetof(EcshShrineState, guessTimer) == 0xC);
STATIC_ASSERT(offsetof(EcshShrineState, voiceTimer) == 0x10);
STATIC_ASSERT(offsetof(EcshShrineState, shuffleSfxThreshold) == 0x14);
STATIC_ASSERT(offsetof(EcshShrineState, spiritCup) == 0x2E);
STATIC_ASSERT(offsetof(EcshShrineState, gameBitLatchState) == 0x34);

#endif
