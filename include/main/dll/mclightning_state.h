#ifndef MAIN_DLL_MCLIGHTNING_STATE_H_
#define MAIN_DLL_MCLIGHTNING_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* mclightning_state_GENERATED
 * McLightningState - the obj+0xB8 extra record observed in mclightning.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct McLightningState {
    void *unk0;
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
    u8 unk18;
    u8 unk19;
    u8 unk1A;
    u8 unk1B[0x20 - 0x1B];
} McLightningState;

#endif /* MAIN_DLL_MCLIGHTNING_STATE_H_ */
