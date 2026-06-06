#ifndef MAIN_DLL_GFXEMIT_STATE_H_
#define MAIN_DLL_GFXEMIT_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* gfxemit_state_GENERATED
 * GfxEmitState - the obj+0xB8 extra record observed in gfxEmit.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct GfxEmitState {
    u8 unk0[0x8 - 0x0];
    f32 delayTimer;
    u8 unkC[0x10 - 0xC];
    s16 hideGameBit;
    u8 unk12[0x14 - 0x12];
    s16 enableGameBit;
    u8 unk16[0x1D - 0x16];
    u8 unk1D;
    u8 enableGameBitClear;
    u8 unk1F[0x30 - 0x1F];
    f32 spinSpeed;
    s16 spinTimer;
    u8 useColor;
    u8 unk37[0x38 - 0x37];
    u8 colorR;
    u8 colorG;
    u8 colorB;
    u8 unk3B[0x3C - 0x3B];
    s16 hideFrames;
    u8 unk3E[0x44 - 0x3E];
    f32 intervalTimer;
    s16 unk48;
    u8 unk4A[0x2B1 - 0x4A];
    u8 unk2B1;
    u8 unk2B2[0x2B8 - 0x2B2];
} GfxEmitState;

#endif /* MAIN_DLL_GFXEMIT_STATE_H_ */
