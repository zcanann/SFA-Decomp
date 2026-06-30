#ifndef MAIN_DLL_TFRAMEANIMATOR_STATE_H_
#define MAIN_DLL_TFRAMEANIMATOR_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* tframeanimator_state_GENERATED
 * TFrameAnimatorState - the obj+0xB8 extra record observed in tFrameAnimator.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct TFrameAnimatorState {
    int textRecord;
    int unk4;
    int duration;
    u8 unkC;
    u8 unkD[0xE - 0xD];
    s16 enableGameBit;
    s16 elapsedFrames;
    s16 bannerY;
    u8 phase;
    u8 unk15[0x268 - 0x15];
    f32 primaryRadius;
    f32 fadeTimer;
    u8 unk270[0x274 - 0x270];
} TFrameAnimatorState;

#endif /* MAIN_DLL_TFRAMEANIMATOR_STATE_H_ */
