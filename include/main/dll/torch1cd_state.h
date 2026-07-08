#ifndef MAIN_DLL_TORCH1CD_STATE_H_
#define MAIN_DLL_TORCH1CD_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* torch1cd_state_GENERATED
 * Torch1CDState - the obj+0xB8 extra record observed in torch1CD.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct Torch1CDState {
    u8 unk0[0x8 - 0x0];
    s16 flameFrame;
    s16 flameFrameVel;
    u8 unkC[0x13 - 0xC];
    u8 phase;
    u8 pendingEvent;
    u8 unk15[0x1C - 0x15];
} Torch1CDState;

#endif /* MAIN_DLL_TORCH1CD_STATE_H_ */
